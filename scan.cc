/* Copyright (c) 2017, 2022, Oracle and/or its affiliates. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2.0,
  as published by the Free Software Foundation.

  This program is also distributed with certain software (including
  but not limited to OpenSSL) that is licensed under separate terms,
  as designated in a particular file or component or in included license
  documentation.  The authors of MySQL hereby grant you an additional
  permission to link the program and your derivative works with the
  separately licensed software that they have included with MySQL.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License, version 2.0, for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#define LOG_COMPONENT_TAG "viruscan"
#define NO_SIGNATURE_CHANGE 0
#define SIGNATURE_CHANGE 1

#include <components/viruscan/scan.h>

REQUIRES_SERVICE_PLACEHOLDER(log_builtins);
REQUIRES_SERVICE_PLACEHOLDER(log_builtins_string);
REQUIRES_SERVICE_PLACEHOLDER(dynamic_privilege_register);
REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
REQUIRES_SERVICE_PLACEHOLDER(mysql_udf_metadata);
REQUIRES_SERVICE_PLACEHOLDER(mysql_thd_security_context);
REQUIRES_SERVICE_PLACEHOLDER(mysql_security_context_options);
REQUIRES_SERVICE_PLACEHOLDER(global_grants_check);
REQUIRES_SERVICE_PLACEHOLDER(mysql_current_thread_reader);
REQUIRES_SERVICE_PLACEHOLDER(mysql_runtime_error);
REQUIRES_SERVICE_PLACEHOLDER(status_variable_registration);

SERVICE_TYPE(log_builtins) * log_bi;
SERVICE_TYPE(log_builtins_string) * log_bs;

static const char *SCAN_PRIVILEGE_NAME = "VIRUS_SCAN";

static unsigned int  signature_status = 0;
static unsigned int  virusfound_status = 0;
static char clamav_version[10] = "";

static SHOW_VAR viruscan_status_variables[] = {
  {"viruscan.clamav_signatures", (char *)&signature_status, SHOW_INT,
    SHOW_SCOPE_GLOBAL},
  {"viruscan.clamav_engine_version", (char *)&clamav_version, SHOW_CHAR,
    SHOW_SCOPE_GLOBAL},
  {"viruscan.virus_found", (char *)&virusfound_status, SHOW_INT,
     SHOW_SCOPE_GLOBAL},
   {nullptr, nullptr, SHOW_LONG, SHOW_SCOPE_GLOBAL}
};


struct scan_result scan_data(const char *data, size_t data_size);

/*
 * Holds the data of a virus scan
 */
struct scan_result
{
  int               return_code;
  const char        *virus_name;
  long unsigned int scanned;
};

/*
 * Global variable to access the ClamAV engine
 */
struct cl_engine *engine = NULL;
char   *signatureDir;
struct cl_stat signatureStat;

class udf_list {
  typedef std::list<std::string> udf_list_t;

 public:
  ~udf_list() { unregister(); }
  bool add_scalar(const char *func_name, enum Item_result return_type,
                  Udf_func_any func, Udf_func_init init_func = NULL,
                  Udf_func_deinit deinit_func = NULL) {
    if (!mysql_service_udf_registration->udf_register(
            func_name, return_type, func, init_func, deinit_func)) {
      set.push_back(func_name);
      return false;
    }
    return true;
  }

  bool unregister() {
    udf_list_t delete_set;
    /* try to unregister all of the udfs */
    for (auto udf : set) {
      int was_present = 0;
      if (!mysql_service_udf_registration->udf_unregister(udf.c_str(),
                                                          &was_present) ||
          !was_present)
        delete_set.push_back(udf);
    }

    /* remove the unregistered ones from the list */
    for (auto udf : delete_set) set.remove(udf);

    /* success: empty set */
    if (set.empty()) return false;

    /* failure: entries still in the set */
    return true;
  }

 private:
  udf_list_t set;
} * list;

unsigned int reload_engine()
{
  unsigned int signatureNum = 0;
  int     rv;

  if (engine != NULL)
  {
    cl_engine_free(engine);
  }

  engine = cl_engine_new();

  memset(&signatureStat, 0, sizeof(struct cl_stat));
  signatureDir = const_cast<char*>(cl_retdbdir());
  cl_statinidir(signatureDir, &signatureStat);
  /*
   * Load the signatures from signatureDir, we use only the default dir
   */
  rv = cl_load(signatureDir, engine, &signatureNum, CL_DB_STDOPT);
  char buf[1024];
  if (CL_SUCCESS != rv)
  {
    snprintf(buf, 1024, "failure loading clamav databases: %s", cl_strerror(rv));
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, buf);
  }

  rv = cl_engine_compile(engine);
  if (CL_SUCCESS != rv)
  {
    snprintf(buf, 1024, "cannot create clamav engine: %s", cl_strerror(rv));
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, buf);
    cl_engine_free(engine);
  }

  snprintf(buf, 1024, "clamav engine loaded with signatureNum %d from %s", signatureNum, signatureDir);
  LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, buf);
  signature_status = signatureNum;
  return signatureNum;
}

int register_status_variables() {
  if (mysql_service_status_variable_registration->register_variable(
          (SHOW_VAR *)&viruscan_status_variables)) {
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "Failed to register status variable");
    return 1;
  }
  LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, "Status variable(s) registered");
  return 0;
}

int unregister_status_variables() {
  if (mysql_service_status_variable_registration->unregister_variable(
          (SHOW_VAR *)&viruscan_status_variables)) {
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "Failed to unregister status variable");
    return 1;
  }
  LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, "Status variable(s) unregistered");
  return 0;
}


namespace udf_impl {

struct scan_result scan_data(const char *data, size_t data_size)
{
  struct scan_result result = {0, "", 0};
  cl_fmap_t *map;

  map = cl_fmap_open_memory(data, data_size);
  /* scan file descriptor */
  static struct cl_scan_options cl_scan_options;
  memset(&cl_scan_options, 0, sizeof(struct cl_scan_options));
  cl_scan_options.parse |= ~0;                           /* enable all parsers */
  cl_scan_options.general |= CL_SCAN_GENERAL_ALLMATCHES;
  result.return_code = cl_scanmap_callback(map,
                          NULL,
                          &result.virus_name,
                          &result.scanned,
                          engine,
                          &cl_scan_options,
                          NULL);

  cl_fmap_close(map);
  return result;
}

bool have_virus_scan_privilege(void *opaque_thd) {
  // get the security context of the thread
  Security_context_handle ctx = nullptr;
  if (mysql_service_mysql_thd_security_context->get(opaque_thd, &ctx) || !ctx) {
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                    "problem trying to get security context");
    return false;
  }

  if (mysql_service_global_grants_check->has_global_grant(
          ctx, SCAN_PRIVILEGE_NAME, strlen(SCAN_PRIVILEGE_NAME)))
    return true;

  return false;
}
	
const char *udf_init = "udf_init", *my_udf = "my_udf",
           *my_udf_clear = "my_clear", *my_udf_add = "my_udf_add";

static bool viruscan_udf_init(UDF_INIT *initid, UDF_ARGS *, char *) {
  const char* name = "utf8mb4";
  char *value = const_cast<char*>(name);
  initid->ptr = const_cast<char *>(udf_init);
  if (mysql_service_mysql_udf_metadata->result_set(
          initid, "charset",
          const_cast<char *>(value))) {
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "failed to set result charset");
    return false;
  }
  return 0;
}

static void viruscan_udf_deinit(__attribute__((unused)) UDF_INIT *initid) {
  assert(initid->ptr == udf_init || initid->ptr == my_udf);
}

const char *viruscan_udf(UDF_INIT *, UDF_ARGS *args, char *outp,
                          unsigned long *length, char *is_null, char *error) {

    MYSQL_THD thd;
    mysql_service_mysql_current_thread_reader->get(&thd);

    struct scan_result result;
    char buf[1024];

    if(!have_virus_scan_privilege(thd)) {
       mysql_error_service_printf(
            ER_SPECIFIC_ACCESS_DENIED_ERROR, 0,
            SCAN_PRIVILEGE_NAME);
       *error = 1;
       *is_null = 1;
       return 0;
    }

    result = scan_data(args->args[0], args->lengths[0]);
    if (result.return_code == 0) {
      strncpy(outp, "clean: no virus found", *length);
    } else {
      strncpy(outp, result.virus_name, *length);
      snprintf(buf, 1024, "Virus found: %s !!", result.virus_name);
      LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, buf);
      virusfound_status++;
      PSI_int signature_psi = {(long)signature_status, false};

      // We need to get some info like user and host
      Security_context_handle ctx = nullptr;
      mysql_service_mysql_thd_security_context->get(thd, &ctx);
      MYSQL_LEX_CSTRING user;
      MYSQL_LEX_CSTRING host;

      mysql_service_mysql_security_context_options->get(ctx, "priv_user",
                                                        &user);

      mysql_service_mysql_security_context_options->get(ctx, "priv_host",
                                                        &host);
      Virus_array_size = addVirus_element(Virus_array_size, virus_array, time(nullptr), result.virus_name, 
                                     user.str, host.str, clamav_version ,signature_psi);      
    }
     
    *length = strlen(outp);
    return const_cast<char *>(outp);
}

static bool virusreload_udf_init(UDF_INIT *initid, UDF_ARGS *, char *) {
  const char* name = "utf8mb4";
  char *value = const_cast<char*>(name);
  initid->ptr = const_cast<char *>(udf_init);
  if (mysql_service_mysql_udf_metadata->result_set(
          initid, "charset",
          const_cast<char *>(value))) {
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "failed to set result charset");
    return false;
  }
  return 0;
}

static void virusreload_udf_deinit(__attribute__((unused)) UDF_INIT *initid) {
  assert(initid->ptr == udf_init || initid->ptr == my_udf);
}

const char *virusreload_udf(UDF_INIT *, UDF_ARGS *args, char *outp,
                          unsigned long *length, char *is_null, char *error) {

    MYSQL_THD thd;
    mysql_service_mysql_current_thread_reader->get(&thd);

    unsigned int signatureNum = 0;

    if(!have_virus_scan_privilege(thd)) {
       mysql_error_service_printf(
            ER_SPECIFIC_ACCESS_DENIED_ERROR, 0,
            SCAN_PRIVILEGE_NAME);
       *error = 1;
       *is_null = 1;
       return 0;
    }

    if (args->arg_count > 0) {
      snprintf(outp, *length, "ERROR: this function doesn't require any parameter !");
      *length = strlen(outp);
      return const_cast<char *>(outp);
    }
    snprintf(outp, *length, "No need to reload ClamAV engine");
    
    if(cl_statchkdir(&signatureStat) == SIGNATURE_CHANGE) {
      signatureNum = reload_engine();
      cl_statfree(&signatureStat);
      cl_statinidir(cl_retdbdir(), &signatureStat);
      snprintf(outp, *length, "ClamAV engine reloaded with new virus database: %d signatures", signatureNum);
    }

    *length = strlen(outp);
    return const_cast<char *>(outp);
}
	

} /* namespace udf_impl */


static mysql_service_status_t viruscan_service_init() {
  mysql_service_status_t result = 0;

  log_bi = mysql_service_log_builtins;
  log_bs = mysql_service_log_builtins_string;

  LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, "initializing...");

  register_status_variables();

  int rv;
  rv = cl_init(CL_INIT_DEFAULT);
  char buf[1024];
  if (CL_SUCCESS != rv) {
    snprintf(buf, 1024, "can't initialize libclamav: %s", cl_strerror(rv));
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, buf);
  } else {
    // Print the version of ClamAV engine
    strncpy(clamav_version, cl_retver(), sizeof(clamav_version)-1);
    snprintf(buf, 1024, "ClamAV %s intialized", clamav_version);
    LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, buf);
  }

  struct cl_engine *cl_engine_new(void);
  reload_engine();

  // Registration of the privilege
  if (mysql_service_dynamic_privilege_register->register_privilege(SCAN_PRIVILEGE_NAME, strlen(SCAN_PRIVILEGE_NAME))) {
          LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                    "could not register privilege 'VIRUS_SCAN'.");
          result = 1;
  } else {
          LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "new privilege 'VIRUS_SCAN' has been registered successfully.");
  }

  list = new udf_list();

  if (list->add_scalar("virus_scan", Item_result::STRING_RESULT,
                       (Udf_func_any)udf_impl::viruscan_udf,
                       udf_impl::viruscan_udf_init,
                       udf_impl::viruscan_udf_deinit)) {
    delete list;
    return 1; /* failure: one of the UDF registrations failed */
  }

  if (list->add_scalar("virus_reload_engine", Item_result::STRING_RESULT,
                       (Udf_func_any)udf_impl::virusreload_udf,
                       udf_impl::virusreload_udf_init,
                       udf_impl::virusreload_udf_deinit)) {
    delete list;
    return 1; /* failure: one of the UDF registrations failed */
  }

  native_mutex_init(&LOCK_virus_records_array, nullptr);
  init_virus_share(&virus_st_share);
  virus_delete_all_rows();
  share_list[0] = &virus_st_share;
  if (mysql_service_pfs_plugin_table->add_tables(&share_list[0],
                                                 share_list_count)) {
    LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                    "PFS table has NOT been registered successfully!");
    native_mutex_destroy(&LOCK_virus_records_array);
    return 1;
  } else{
    LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "PFS table has been registered successfully.");
  }

  return result;
}

static mysql_service_status_t viruscan_service_deinit() {
  mysql_service_status_t result = 0;
  
  cl_engine_free(engine);

  unregister_status_variables();

  if (mysql_service_dynamic_privilege_register->unregister_privilege(SCAN_PRIVILEGE_NAME, strlen(SCAN_PRIVILEGE_NAME))) {
          LogComponentErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                    "could not unregister privilege 'VIRUS_SCAN'.");
          result = 1;
  } else {
          LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "privilege 'VIRUS_SCAN' has been unregistered successfully.");
  }

  if (list->unregister()) return 1; /* failure: some UDFs still in use */

  delete list;

  LogComponentErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG, "uninstalled.");

  native_mutex_destroy(&LOCK_virus_records_array);

  return result;
}

BEGIN_COMPONENT_PROVIDES(viruscan_service)
END_COMPONENT_PROVIDES();

BEGIN_COMPONENT_REQUIRES(viruscan_service)
    REQUIRES_SERVICE(log_builtins),
    REQUIRES_SERVICE(log_builtins_string),
    REQUIRES_SERVICE(dynamic_privilege_register),
    REQUIRES_SERVICE(mysql_udf_metadata),
    REQUIRES_SERVICE(udf_registration),
    REQUIRES_SERVICE(mysql_thd_security_context),
    REQUIRES_SERVICE(mysql_security_context_options),
    REQUIRES_SERVICE(global_grants_check),
    REQUIRES_SERVICE(mysql_current_thread_reader),
    REQUIRES_SERVICE(mysql_runtime_error),
    REQUIRES_SERVICE(status_variable_registration),
    REQUIRES_SERVICE(pfs_plugin_table),
    REQUIRES_SERVICE_AS(pfs_plugin_column_integer_v1, pfs_integer),
    REQUIRES_SERVICE_AS(pfs_plugin_column_string_v1, pfs_string),
    REQUIRES_SERVICE_AS(pfs_plugin_column_timestamp_v2, pfs_timestamp),  
END_COMPONENT_REQUIRES();

/* A list of metadata to describe the Component. */
BEGIN_COMPONENT_METADATA(viruscan_service)
METADATA("mysql.author", "Oracle Corporation"),
    METADATA("mysql.license", "GPL"), METADATA("mysql.dev", "lefred"),
END_COMPONENT_METADATA();

/* Declaration of the Component. */
DECLARE_COMPONENT(viruscan_service,
                  "mysql:viruscan_service")
viruscan_service_init,
    viruscan_service_deinit END_DECLARE_COMPONENT();

/* Defines list of Components contained in this library. Note that for now
  we assume that library will have exactly one Component. */
DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(viruscan_service)
    END_DECLARE_LIBRARY_COMPONENTS


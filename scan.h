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

#include <mysql/components/component_implementation.h>
#include <mysql/components/services/log_builtins.h> /* LogComponentErr */
#include <mysqld_error.h>                           /* Errors */
#include <mysql/components/services/dynamic_privilege.h>
#include <mysql/components/services/mysql_current_thread_reader.h>
#include <mysql/components/services/udf_metadata.h>
#include <mysql/components/services/udf_registration.h>
#include <mysql/components/services/security_context.h>
#include <mysql/components/services/mysql_runtime_error_service.h>
#include <mysql/components/services/component_status_var_service.h>
#include <mysql/components/services/pfs_plugin_table_service.h>
#include <mysql/components/services/mysql_mutex.h>

#include <list>
#include <string>

#include <clamav.h>

#include <my_systime.h>

extern REQUIRES_SERVICE_PLACEHOLDER(log_builtins);
extern REQUIRES_SERVICE_PLACEHOLDER(log_builtins_string);
extern REQUIRES_SERVICE_PLACEHOLDER(dynamic_privilege_register);
extern REQUIRES_SERVICE_PLACEHOLDER(udf_registration);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_udf_metadata);

extern REQUIRES_SERVICE_PLACEHOLDER(mysql_current_thread_reader);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_thd_security_context);
extern REQUIRES_SERVICE_PLACEHOLDER(mysql_security_context_options);
extern REQUIRES_SERVICE_PLACEHOLDER(global_grants_check);

extern REQUIRES_SERVICE_PLACEHOLDER(mysql_runtime_error);

extern REQUIRES_SERVICE_PLACEHOLDER(status_variable_registration);

extern REQUIRES_SERVICE_PLACEHOLDER(pfs_plugin_table);
extern REQUIRES_SERVICE_PLACEHOLDER_AS(pfs_plugin_column_integer_v1, pfs_integer);
extern REQUIRES_SERVICE_PLACEHOLDER_AS(pfs_plugin_column_string_v1, pfs_string);
extern REQUIRES_SERVICE_PLACEHOLDER_AS(pfs_plugin_column_timestamp_v2, pfs_timestamp);

extern REQUIRES_MYSQL_MUTEX_SERVICE_PLACEHOLDER;


extern SERVICE_TYPE(log_builtins) * log_bi;
extern SERVICE_TYPE(log_builtins_string) * log_bs;


/* Global share pointer for pfs_viruscan_matches table */
extern PFS_engine_table_share_proxy viruscan_st_share;

/* Maximum number of rows in the table */
// #define VIRUS_MAX_ROWS 1024
#define VIRUS_MAX_ROWS 10
#define VIRUS_NAME_MAX_LENGTH 4 * 100
#define USERNAME_MAX_LENGTH 4 *32
#define HOSTNAME_MAX_LENGTH 4* 255

void init_virus_data();
void cleanup_virus_data();


struct Virus_record {
  time_t virus_timestamp;
  std::string virus_name;
  std::string virus_username;
  std::string virus_hostname;
  std::string virus_engine;
  PSI_int virus_signatures;
};

class Virus_POS {
 private:
  unsigned int m_index = 0;

 public:
  ~Virus_POS() = default;
  Virus_POS() { m_index = 0; }

  void reset() { m_index = 0; }

  unsigned int get_index() { return m_index; }

  void set_at(Virus_POS *pos) { m_index = pos->m_index; }

  void set_after(Virus_POS *pos) { m_index = pos->m_index + 1; }
};

struct Virus_Table_Handle {
  /* Current position instance */
  Virus_POS m_pos;
  /* Next position instance */
  Virus_POS m_next_pos;

  /* Current row for the table */
  Virus_record current_row;

  /* Index indicator */
  unsigned int index_num;
};

void init_virus_share(PFS_engine_table_share_proxy *share);

extern PFS_engine_table_share_proxy virus_st_share;

extern PFS_engine_table_share_proxy *share_list[];
extern unsigned int share_list_count;

static mysql_mutex_t LOCK_virus_data;
extern PSI_mutex_key key_mutex_virus_data;
extern PSI_mutex_info virus_data_mutex[];

extern void addVirus_element(time_t virus_timestamp,
                    std::string virus_name, std::string virus_username, std::string virus_hostname,
                    std::string virus_engine, PSI_int virus_signatures);

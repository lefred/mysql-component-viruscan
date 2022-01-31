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

#include <components/viruscan/scan.h>

#include <array>

REQUIRES_SERVICE_PLACEHOLDER(pfs_plugin_table);
REQUIRES_SERVICE_PLACEHOLDER_AS(pfs_plugin_column_integer_v1, pfs_integer);
REQUIRES_SERVICE_PLACEHOLDER_AS(pfs_plugin_column_string_v1, pfs_string);
REQUIRES_SERVICE_PLACEHOLDER_AS(pfs_plugin_column_timestamp_v2, pfs_timestamp);

/*
  DATA
*/

native_mutex_t LOCK_virus_data;

static std::array<Virus_record *, VIRUS_MAX_ROWS> virus_array;

/* Next available index for new record to be stored in global record array. */
static size_t virus_next_available_index = 0;

void init_virus_data() {
  native_mutex_lock(&LOCK_virus_data);
  virus_next_available_index = 0;
  virus_array.fill(nullptr);
  native_mutex_unlock(&LOCK_virus_data);
}

void cleanup_virus_data() {
  native_mutex_lock(&LOCK_virus_data);
  for (Virus_record *virus : virus_array) {
    delete virus;
  }
  native_mutex_unlock(&LOCK_virus_data);
}

/*
  DATA collection
*/

void addVirus_element(time_t virus_timestamp, std::string virus_name,
                      std::string virus_username, std::string virus_hostname,
                      std::string virus_engine, PSI_int virus_signatures) {
  size_t index;
  Virus_record *record;

  native_mutex_lock(&LOCK_virus_data);

  index = virus_next_available_index++ % VIRUS_MAX_ROWS;
  record = virus_array[index];

  if (record != nullptr) {
    delete record;
  }

  record = new Virus_record;
  record->virus_timestamp = virus_timestamp;
  record->virus_name = virus_name;
  record->virus_username = virus_username;
  record->virus_hostname = virus_hostname;
  record->virus_engine = virus_engine;
  record->virus_signatures = virus_signatures;

  virus_array[index] = record;

  native_mutex_unlock(&LOCK_virus_data);
}

/*
  DATA access (performance schema table)
*/

/* Collection of table shares to be added to performance schema */
PFS_engine_table_share_proxy *share_list[1] = {nullptr};
unsigned int share_list_count = 1;

/* Global share pointer for a table */
PFS_engine_table_share_proxy virus_st_share;

int virus_delete_all_rows(void) {
  cleanup_virus_data();
  return 0;
}

PSI_table_handle *virus_open_table(PSI_pos **pos) {
  Virus_Table_Handle *temp = new Virus_Table_Handle();
  *pos = (PSI_pos *)(&temp->m_pos);
  return (PSI_table_handle *)temp;
}

void virus_close_table(PSI_table_handle *handle) {
  Virus_Table_Handle *temp = (Virus_Table_Handle *)handle;
  delete temp;
}

static void copy_record_virus(Virus_record *dest, const Virus_record *source) {
  dest->virus_timestamp = source->virus_timestamp;
  dest->virus_name = source->virus_name;
  dest->virus_username = source->virus_username;
  dest->virus_hostname = source->virus_hostname;
  dest->virus_engine = source->virus_engine;
  dest->virus_signatures = source->virus_signatures;
  return;
}

/* Define implementation of PFS_engine_table_proxy. */
int virus_rnd_next(PSI_table_handle *handle) {
  Virus_Table_Handle *h = (Virus_Table_Handle *)handle;
  h->m_pos.set_at(&h->m_next_pos);
  size_t index = h->m_pos.get_index();

  if (index < virus_array.size()) {
    Virus_record *record = virus_array[index];
    if (record != nullptr) {
      /* Make the current row from records_array buffer */
      copy_record_virus(&h->current_row, record);
      h->m_next_pos.set_after(&h->m_pos);
      return 0;
    }
  }

  return PFS_HA_ERR_END_OF_FILE;
}

int virus_rnd_init(PSI_table_handle *, bool) { return 0; }

/* Set position of a cursor on a specific index */
int virus_rnd_pos(PSI_table_handle *handle) {
  Virus_Table_Handle *h = (Virus_Table_Handle *)handle;
  size_t index = h->m_pos.get_index();

  if (index < virus_array.size()) {
    Virus_record *record = virus_array[index];

    if (record != nullptr) {
      /* Make the current row from records_array buffer */
      copy_record_virus(&h->current_row, record);
    }
  }

  return 0;
}

/* Reset cursor position */
void virus_reset_position(PSI_table_handle *handle) {
  Virus_Table_Handle *h = (Virus_Table_Handle *)handle;
  h->m_pos.reset();
  h->m_next_pos.reset();
  return;
}

/* Read current row from the current_row and display them in the table */
int virus_read_column_value(PSI_table_handle *handle, PSI_field *field,
                            unsigned int index) {
  Virus_Table_Handle *h = (Virus_Table_Handle *)handle;

  switch (index) {
    case 0: /* LOGGED */
      pfs_timestamp->set2(field, (h->current_row.virus_timestamp * 1000000));
      break;
    case 1: /* VIRUS */
      pfs_string->set_varchar_utf8mb4(field, h->current_row.virus_name.c_str());
      break;
    case 2: /* USER */
      pfs_string->set_varchar_utf8mb4(field,
                                      h->current_row.virus_username.c_str());
      break;
    case 3: /* HOST */
      pfs_string->set_varchar_utf8mb4(field,
                                      h->current_row.virus_hostname.c_str());
      break;
    case 4: /* CLAMVERSION */
      pfs_string->set_varchar_utf8mb4(field,
                                      h->current_row.virus_engine.c_str());
      break;
    case 5: /* SIGNATURES */
      pfs_integer->set(field, h->current_row.virus_signatures);
      break;
    default: /* We should never reach here */
      assert(0);
      break;
  }
  return 0;
}

unsigned long long virus_get_row_count(void) { return VIRUS_MAX_ROWS; }

void init_virus_share(PFS_engine_table_share_proxy *share) {
  /* Instantiate and initialize PFS_engine_table_share_proxy */
  share->m_table_name = "viruscan_matches";
  share->m_table_name_length = 16;
  share->m_table_definition =
      "`LOGGED` timestamp, `VIRUS` VARCHAR(100), `USER` VARCHAR(32), "
      "`HOST` VARCHAR(255), `CLAMVERSION` VARCHAR(10), `SIGNATURES` INT";
  share->m_ref_length = sizeof(Virus_POS);
  share->m_acl = READONLY;
  share->get_row_count = virus_get_row_count;
  share->delete_all_rows = nullptr; /* READONLY TABLE */

  /* Initialize PFS_engine_table_proxy */
  share->m_proxy_engine_table = {virus_rnd_next, virus_rnd_init, virus_rnd_pos,
                                 nullptr, nullptr, nullptr,
                                 virus_read_column_value, virus_reset_position,
                                 /* READONLY TABLE */
                                 nullptr, /* write_column_value */
                                 nullptr, /* write_row_values */
                                 nullptr, /* update_column_value */
                                 nullptr, /* update_row_values */
                                 nullptr, /* delete_row_values */
                                 virus_open_table, virus_close_table};
}

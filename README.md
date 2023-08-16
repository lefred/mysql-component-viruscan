# mysql-component-viruscan
Extending MySQL using the Component Infrastructure - Code example

This component is an example used during the Extending MySQL using the Component Infrastructure series published on https://lefred.be:

* [Extending MySQL using the Component Infrastructure – part 1](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-1/)
* [Extending MySQL using the Component Infrastructure – part 2: building the server](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-2-building-the-server/)
* [Extending MySQL using the Component Infrastructure – part 3: component services](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-3-component-services/)
* [Extending MySQL using the Component Infrastructure – part 4: error logging](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-4-error-logging/)
* [Extending MySQL using the Component Infrastructure – part 5: privileges](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-5-privileges/)
* [Extending MySQL using the Component Infrastructure – part 6: functions](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-6-functions/)
* [Extending MySQL using the Component Infrastructure – part 7: messages to users](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-7-messages-to-users/)
* [Extending MySQL using the Component Infrastructure – part 8: linking a third party library](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-8-linking-a-third-party-library/)
* [Extending MySQL using the Component Infrastructure – part 9: adding a new function](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-9-adding-a-new-function/)
* [Extending MySQL using the Component Infrastructure – part 10: status variables](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-10-status-variables/)
* [Extending MySQL using the Component Infrastructure – part 11: performance_schema table](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-11-performance_schema-table/)
* [Extending MySQL using the Component Infrastructure – part 12 : instrument your code](https://lefred.be/content/extending-mysql-using-the-component-infrastructure-part-12-instrument-your-code/)

# How to use

## Installation

```
$ sudo rpm -ivh mysql-community-component-viruscan-8.1.0-10.fc38.x86_64.rpm
$ mysqlsh mysql://root@localhost

MySQL > install component "file://component_viruscan";
Query OK, 0 rows affected (0.0276 sec)

MySQL > select * from performance_schema.error_log where subsystem="server" and data like 'Component viruscan%';
+----------------------------+-----------+-------+------------+-----------+-----------------------------------------------------------------------------------------------+
| LOGGED                     | THREAD_ID | PRIO  | ERROR_CODE | SUBSYSTEM | DATA                                                                                          |
+----------------------------+-----------+-------+------------+-----------+-----------------------------------------------------------------------------------------------+
| 2023-08-16 14:45:58.781052 |         9 | Note  | MY-011071  | Server    | Component viruscan reported: 'initializing...'                                                |
| 2023-08-16 14:45:58.781499 |         9 | Note  | MY-011071  | Server    | Component viruscan reported: 'Status variable(s) registered'                                  |
| 2023-08-16 14:45:58.781627 |         9 | Note  | MY-011071  | Server    | Component viruscan reported: 'ClamAV 1.0.1 intialized'                                        |
| 2023-08-16 14:45:58.783058 |         9 | Error | MY-011071  | Server    | Component viruscan reported: 'failure loading clamav databases: Can't open file or directory' |
| 2023-08-16 14:45:58.783957 |         9 | Note  | MY-011071  | Server    | Component viruscan reported: 'clamav engine loaded with signatureNum 0 from /var/lib/clamav'  |
| 2023-08-16 14:45:58.783993 |         9 | Note  | MY-011071  | Server    | Component viruscan reported: 'new privilege 'VIRUS_SCAN' has been registered successfully.'   |
| 2023-08-16 14:45:58.785867 |         9 | Note  | MY-011071  | Server    | Component viruscan reported: 'PFS table has been registered successfully.'                    |
+----------------------------+-----------+-------+------------+-----------+-----------------------------------------------------------------------------------------------+
7 rows in set (0.0067 sec)
```

Pay attention that there is an error reported by the clamav engine.
You can also notice the value of the status variable `viruscan.clamav_signatures` being `0`.

Run: 

```
$ sudo freshclam
```

And then you need to reload the engine:

```
MySQL > select virus_reload_engine();
```

## UDF Functions

``` MySQL > select * from performance_schema.user_defined_functions 
            where udf_name like 'virus%';
+---------------------+-----------------+----------+-------------+-----------------+
| UDF_NAME            | UDF_RETURN_TYPE | UDF_TYPE | UDF_LIBRARY | UDF_USAGE_COUNT |
+---------------------+-----------------+----------+-------------+-----------------+
| virus_reload_engine | char            | function | NULL        |               1 |
| virus_scan          | char            | function | NULL        |               1 |
+---------------------+-----------------+----------+-------------+-----------------+
2 rows in set (0.0008 sec)
```

## Usage

```
MySQL > select virus_scan("lefred");
ERROR: 1227 (42000): Access denied; you need (at least one of) the VIRUS_SCAN privilege(s) for this operation

MySQL > grant VIRUS_SCAN on *.* to root;
Query OK, 0 rows affected (0.0150 sec)

MySQL > select virus_scan("lefred");
+-----------------------+
| virus_scan("lefred")  |
+-----------------------+
| clean: no virus found |
+-----------------------+
1 row in set (0.0013 sec)

MySQL > show global status like 'viruscan.%';
+--------------------------------+-------+
| Variable_name                  | Value |
+--------------------------------+-------+
| viruscan.clamav_engine_version | 1.0.1 |
| viruscan.clamav_signatures     | 0     |
| viruscan.virus_found           | 0     |
+--------------------------------+-------+
3 rows in set (0.0026 sec)

select virus_scan("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
+-------------------------------------------------------------------------------------+
| virus_scan("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") |
+-------------------------------------------------------------------------------------+
| Eicar-Signature                                                                     |
+-------------------------------------------------------------------------------------+
1 row in set (0.0083 sec)

MySQL > show global status like 'viruscan.virus_found';
+----------------------+-------+
| Variable_name        | Value |
+----------------------+-------+
| viruscan.virus_found | 1     |
+----------------------+-------+
1 row in set (0.0021 sec)
```

## Performance_Schema 
 
```
MySQL > select * from performance_schema.viruscan_matches;
+---------------------+-----------------+------+-----------+-------------+------------+
| LOGGED              | VIRUS           | USER | HOST      | CLAMVERSION | SIGNATURES |
+---------------------+-----------------+------+-----------+-------------+------------+
| 2023-08-16 15:09:24 | Eicar-Signature | root | localhost | 1.0.1       |    8671805 |
+---------------------+-----------------+------+-----------+-------------+------------+
1 row in set (0.0007 sec)
```
## Updating the virus database

As for the installation, you need to upgrade the clamav engine and database using `freshclam` and then reload the engine and verify the version:

```
MySQL > select virus_reload_engine();
+--------------------------------------------------------------------+
| virus_reload_engine()                                              |
+--------------------------------------------------------------------+
| ClamAV engine reloaded with new virus database: 8671805 signatures |
+--------------------------------------------------------------------+
1 row in set (10.8586 sec)

MySQL > select * from performance_schema.error_log 
        where subsystem="server" and data like 'Component viruscan%' 
        order by logged desc limit 1\G
*************************** 1. row ***************************
    LOGGED: 2023-08-16 15:07:29.675698
 THREAD_ID: 9
      PRIO: Note
ERROR_CODE: MY-011071
 SUBSYSTEM: Server
      DATA: Component viruscan reported: 'clamav engine loaded with signatureNum 8671805 from /var/lib/clamav'
1 row in set (0.0066 sec)

MySQL > show global status like 'viruscan.clamav_%';
+--------------------------------+---------+
| Variable_name                  | Value   |
+--------------------------------+---------+
| viruscan.clamav_engine_version | 1.0.1   |
| viruscan.clamav_signatures     | 8671805 |
+--------------------------------+---------+
2 rows in set (0.0021 sec)
```

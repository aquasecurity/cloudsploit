var expect = require("chai").expect;
var rdsLogConnectionEnabled = require("./rdsLogConnectionEnabled.js");

const describeDBInstances = [
  {
    EngineVersion: "13.0",
    DBInstanceStatus: "Running",
    ResourceGroupId: "rg-aekzsj44b4lt5fa",
    DBInstanceNetType: "Intranet",
    DBInstanceClass: "pg.n2.small.2c",
    CreateTime: "2021-05-04T17:13:45Z",
    VSwitchId: "vsw-rj94uhhrj5qz5008lwi1x",
    DBInstanceType: "Primary",
    PayType: "Postpaid",
    LockMode: "Unlock",
    MutriORsignle: false,
    InstanceNetworkType: "VPC",
    InsId: 1,
    VpcId: "vpc-rj9vu86hdve3qr173ew17",
    DBInstanceId: "pgm-2ev213kfnogf7mfi",
    ConnectionMode: "Standard",
    ReadOnlyDBInstanceIds: {
      ReadOnlyDBInstanceId: [],
    },
    VpcCloudInstanceId: "pgm-2ev213kfnogf7mfi",
    ExpireTime: "",
    LockReason: "",
    Engine: "PostgreSQL",
  },
];

const describeParameters = [
  {
    RunningParameters: {
      DBInstanceParameter: [
        {
          ParameterValue: "0",
          ParameterName: "autovacuum_vacuum_cost_delay",
          ParameterDescription:
            "Vacuum cost delay in milliseconds, for autovacuum.",
        },
        {
          ParameterValue: "10000",
          ParameterName: "autovacuum_vacuum_cost_limit",
          ParameterDescription:
            "Vacuum cost amount available before napping, for autovacuum.",
        },
        {
          ParameterValue: "0.02",
          ParameterName: "autovacuum_vacuum_scale_factor",
          ParameterDescription:
            "When the table is updated or deleted tuples exceed autovacuum_vacuum_threshold + autovacuum_vacuum_scale_factor * the total number of table tuples triggers automatic cleanup.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_analyze",
          ParameterDescription: "Use EXPLAIN ANALYZE for plan logging.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_buffers",
          ParameterDescription: "Log buffers usage.",
        },
        {
          ParameterValue: "text",
          ParameterName: "auto_explain.log_format",
          ParameterDescription: "EXPLAIN format to be used for plan logging.",
        },
        {
          ParameterValue: "-1",
          ParameterName: "auto_explain.log_min_duration",
          ParameterDescription:
            "Sets the minimum execution time above which plans will be logged. Zero prints all plans. -1 turns this feature off.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_nested_statements",
          ParameterDescription: "Log nested statements.",
        },
        {
          ParameterValue: "on",
          ParameterName: "auto_explain.log_timing",
          ParameterDescription: "Collect timing data, not just row counts.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_triggers",
          ParameterDescription:
            "Include trigger statistics in plans. This has no effect unless log_analyze is also set.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_verbose",
          ParameterDescription: "Use EXPLAIN VERBOSE for plan logging.",
        },
        {
          ParameterValue: "1",
          ParameterName: "auto_explain.sample_rate",
          ParameterDescription: "Fraction of queries to process.",
        },
        {
          ParameterValue: "off",
          ParameterName: "default_transaction_deferrable",
          ParameterDescription:
            "Sets the default deferrable status of new transactions.",
        },
        {
          ParameterValue: "on",
          ParameterName: "enable_partitionwise_aggregate",
          ParameterDescription:
            "Enables partitionwise aggregation and grouping.",
        },
        {
          ParameterValue: "on",
          ParameterName: "enable_partitionwise_join",
          ParameterDescription: "Enables partitionwise join.",
        },
        {
          ParameterValue: "0",
          ParameterName: "extra_float_digits",
          ParameterDescription:
            "Sets the number of digits displayed for floating-point values.",
        },
        {
          ParameterValue: "3600000",
          ParameterName: "idle_in_transaction_session_timeout",
          ParameterDescription:
            "Sets the maximum allowed duration of any idling transaction. A value of 0 turns off the timeout.",
        },
        {
          ParameterValue: "off",
          ParameterName: "jit",
          ParameterDescription: "allow JIT compilation",
        },
        {
          ParameterValue: "0",
          ParameterName: "lock_timeout",
          ParameterDescription:
            "Sets the maximum allowed duration of any wait for a lock. A value of 0 turns off the timeout.",
        },
        {
          ParameterValue: "off",
          ParameterName: "log_connections",
          ParameterDescription: "Logs each successful connection.",
        },
        {
          ParameterValue: "off",
          ParameterName: "log_disconnections",
          ParameterDescription: "Logs end of a session, including duration.",
        },
        {
          ParameterValue: "1000",
          ParameterName: "log_min_duration_statement",
          ParameterDescription:
            "SQL with execution time exceeding this value will be logged. Note that a too small value may cause performance degradation and increase the amount of logs.",
        },
        {
          ParameterValue: "ddl",
          ParameterName: "log_statement",
          ParameterDescription:
            "Sets the type of statements logged. Setting it to all or mod will cause performance degradation and increase the amount of logs.",
        },
        {
          ParameterValue: "131072",
          ParameterName: "log_temp_files",
          ParameterDescription:
            "Log the use of temporary files larger than this number of kilobyte. Zero logs all files. The default is -1 turning this feature off.",
        },
        {
          ParameterValue: "-1",
          ParameterName: "old_snapshot_threshold",
          ParameterDescription:
            "Time before a snapshot is too old to read pages changed after the snapshot was taken.",
        },
        {
          ParameterValue: "20",
          ParameterName: "rds_max_log_files",
          ParameterDescription:
            "Sets the maximum number of log files. Each log file is 100 MB in size.",
        },
        {
          ParameterValue: "0",
          ParameterName: "rds_sync_replication_timeout",
          ParameterDescription:
            "The maximum time in milliseconds to wait for WAL synchronous replication. When it is timeout, synchronous replication change to asynchronous replication until replication is catchup.",
        },
        {
          ParameterValue: "disable",
          ParameterName: "sql_firewall.firewall",
          ParameterDescription:
            "The parameter is to detemine running mode of sql_firewall extension.",
        },
        {
          ParameterValue: "TLSv1",
          ParameterName: "ssl_min_protocol_version",
          ParameterDescription:
            "Sets the minimum SSL/TLS protocol version to use",
        },
        {
          ParameterValue: "0",
          ParameterName: "statement_timeout",
          ParameterDescription:
            "Sets the maximum allowed duration of any statement. A value of 0 turns off the timeout.",
        },
        {
          ParameterValue: "off",
          ParameterName: "synchronous_commit",
          ParameterDescription:
            "Sets the current transaction's synchronization level.",
        },
        {
          ParameterValue: "''",
          ParameterName: "synchronous_standby_names",
          ParameterDescription:
            "Number of synchronous standbys and list of names of potential synchronous ones.",
        },
        {
          ParameterValue: "Asia/Shanghai",
          ParameterName: "timezone",
          ParameterDescription: "timezone",
        },
        {
          ParameterValue: "off",
          ParameterName: "track_commit_timestamp",
          ParameterDescription: "Collects transaction commit time.",
        },
        {
          ParameterValue: "0",
          ParameterName: "vacuum_defer_cleanup_age",
          ParameterDescription:
            "Number of transactions by which VACUUM and HOT cleanup should be deferred, if any.",
        },
        {
          ParameterValue: "1024",
          ParameterName: "wal_keep_size",
          ParameterDescription:
            "Sets the size of WAL files held for standby servers (MB)",
        },
        {
          ParameterValue: "replica",
          ParameterName: "wal_level",
          ParameterDescription:
            "Set the level of information written to the WAL.",
        },
      ],
    },
    EngineVersion: "13.0",
    RequestId: "F9FF62D1-C157-4893-A095-EB45E6F6F36A",
    ConfigParameters: {
      DBInstanceParameter: [],
    },
    Engine: "PostgreSQL",
  },
  {
    RunningParameters: {
      DBInstanceParameter: [
        {
          ParameterValue: "0",
          ParameterName: "autovacuum_vacuum_cost_delay",
          ParameterDescription:
            "Vacuum cost delay in milliseconds, for autovacuum.",
        },
        {
          ParameterValue: "10000",
          ParameterName: "autovacuum_vacuum_cost_limit",
          ParameterDescription:
            "Vacuum cost amount available before napping, for autovacuum.",
        },
        {
          ParameterValue: "0.02",
          ParameterName: "autovacuum_vacuum_scale_factor",
          ParameterDescription:
            "When the table is updated or deleted tuples exceed autovacuum_vacuum_threshold + autovacuum_vacuum_scale_factor * the total number of table tuples triggers automatic cleanup.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_analyze",
          ParameterDescription: "Use EXPLAIN ANALYZE for plan logging.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_buffers",
          ParameterDescription: "Log buffers usage.",
        },
        {
          ParameterValue: "text",
          ParameterName: "auto_explain.log_format",
          ParameterDescription: "EXPLAIN format to be used for plan logging.",
        },
        {
          ParameterValue: "-1",
          ParameterName: "auto_explain.log_min_duration",
          ParameterDescription:
            "Sets the minimum execution time above which plans will be logged. Zero prints all plans. -1 turns this feature off.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_nested_statements",
          ParameterDescription: "Log nested statements.",
        },
        {
          ParameterValue: "on",
          ParameterName: "auto_explain.log_timing",
          ParameterDescription: "Collect timing data, not just row counts.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_triggers",
          ParameterDescription:
            "Include trigger statistics in plans. This has no effect unless log_analyze is also set.",
        },
        {
          ParameterValue: "off",
          ParameterName: "auto_explain.log_verbose",
          ParameterDescription: "Use EXPLAIN VERBOSE for plan logging.",
        },
        {
          ParameterValue: "1",
          ParameterName: "auto_explain.sample_rate",
          ParameterDescription: "Fraction of queries to process.",
        },
        {
          ParameterValue: "off",
          ParameterName: "default_transaction_deferrable",
          ParameterDescription:
            "Sets the default deferrable status of new transactions.",
        },
        {
          ParameterValue: "on",
          ParameterName: "enable_partitionwise_aggregate",
          ParameterDescription:
            "Enables partitionwise aggregation and grouping.",
        },
        {
          ParameterValue: "on",
          ParameterName: "enable_partitionwise_join",
          ParameterDescription: "Enables partitionwise join.",
        },
        {
          ParameterValue: "0",
          ParameterName: "extra_float_digits",
          ParameterDescription:
            "Sets the number of digits displayed for floating-point values.",
        },
        {
          ParameterValue: "3600000",
          ParameterName: "idle_in_transaction_session_timeout",
          ParameterDescription:
            "Sets the maximum allowed duration of any idling transaction. A value of 0 turns off the timeout.",
        },
        {
          ParameterValue: "off",
          ParameterName: "jit",
          ParameterDescription: "allow JIT compilation",
        },
        {
          ParameterValue: "0",
          ParameterName: "lock_timeout",
          ParameterDescription:
            "Sets the maximum allowed duration of any wait for a lock. A value of 0 turns off the timeout.",
        },
        {
          ParameterValue: "on",
          ParameterName: "log_connections",
          ParameterDescription: "Logs each successful connection.",
        },
        {
          ParameterValue: "on",
          ParameterName: "log_disconnections",
          ParameterDescription: "Logs end of a session, including duration.",
        },
        {
          ParameterValue: "1000",
          ParameterName: "log_min_duration_statement",
          ParameterDescription:
            "SQL with execution time exceeding this value will be logged. Note that a too small value may cause performance degradation and increase the amount of logs.",
        },
        {
          ParameterValue: "ddl",
          ParameterName: "log_statement",
          ParameterDescription:
            "Sets the type of statements logged. Setting it to all or mod will cause performance degradation and increase the amount of logs.",
        },
        {
          ParameterValue: "131072",
          ParameterName: "log_temp_files",
          ParameterDescription:
            "Log the use of temporary files larger than this number of kilobyte. Zero logs all files. The default is -1 turning this feature off.",
        },
        {
          ParameterValue: "-1",
          ParameterName: "old_snapshot_threshold",
          ParameterDescription:
            "Time before a snapshot is too old to read pages changed after the snapshot was taken.",
        },
        {
          ParameterValue: "20",
          ParameterName: "rds_max_log_files",
          ParameterDescription:
            "Sets the maximum number of log files. Each log file is 100 MB in size.",
        },
        {
          ParameterValue: "0",
          ParameterName: "rds_sync_replication_timeout",
          ParameterDescription:
            "The maximum time in milliseconds to wait for WAL synchronous replication. When it is timeout, synchronous replication change to asynchronous replication until replication is catchup.",
        },
        {
          ParameterValue: "disable",
          ParameterName: "sql_firewall.firewall",
          ParameterDescription:
            "The parameter is to detemine running mode of sql_firewall extension.",
        },
        {
          ParameterValue: "TLSv1",
          ParameterName: "ssl_min_protocol_version",
          ParameterDescription:
            "Sets the minimum SSL/TLS protocol version to use",
        },
        {
          ParameterValue: "0",
          ParameterName: "statement_timeout",
          ParameterDescription:
            "Sets the maximum allowed duration of any statement. A value of 0 turns off the timeout.",
        },
        {
          ParameterValue: "off",
          ParameterName: "synchronous_commit",
          ParameterDescription:
            "Sets the current transaction's synchronization level.",
        },
        {
          ParameterValue: "''",
          ParameterName: "synchronous_standby_names",
          ParameterDescription:
            "Number of synchronous standbys and list of names of potential synchronous ones.",
        },
        {
          ParameterValue: "Asia/Shanghai",
          ParameterName: "timezone",
          ParameterDescription: "timezone",
        },
        {
          ParameterValue: "off",
          ParameterName: "track_commit_timestamp",
          ParameterDescription: "Collects transaction commit time.",
        },
        {
          ParameterValue: "0",
          ParameterName: "vacuum_defer_cleanup_age",
          ParameterDescription:
            "Number of transactions by which VACUUM and HOT cleanup should be deferred, if any.",
        },
        {
          ParameterValue: "1024",
          ParameterName: "wal_keep_size",
          ParameterDescription:
            "Sets the size of WAL files held for standby servers (MB)",
        },
        {
          ParameterValue: "replica",
          ParameterName: "wal_level",
          ParameterDescription:
            "Set the level of information written to the WAL.",
        },
      ],
    },
    EngineVersion: "13.0",
    RequestId: "F9FF62D1-C157-4893-A095-EB45E6F6F36A",
    ConfigParameters: {
      DBInstanceParameter: [],
    },
    Engine: "PostgreSQL",
  },
];

const createCache = (
  dbInstances,
  describeParameters,
  dbInstancesErr,
  describeParametersErr
) => {
  let instanceId =
    dbInstances && dbInstances.length ? dbInstances[0].DBInstanceId : null;
  return {
    rds: {
      DescribeDBInstances: {
        "cn-hangzhou": {
          data: dbInstances,
          err: dbInstancesErr,
        },
      },
      DescribeParameters: {
        "cn-hangzhou": {
          [instanceId]: {
            data: describeParameters,
            err: describeParametersErr,
          },
        },
      },
    },
  };
};

describe("rdsLogConnectionEnabled", function () {
  describe("run", function () {
    it("should FAIL if RDS DB instance does not have log_connections parameter enabled", function (done) {
      const cache = createCache(describeDBInstances, describeParameters[0]);
      rdsLogConnectionEnabled.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include(
          "RDS DB instance does not have log_connections parameter enabled"
        );
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should PASS if RDS DB instance has log_connections parameter enabled", function (done) {
      const cache = createCache(describeDBInstances, describeParameters[1]);
      rdsLogConnectionEnabled.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include(
          "RDS DB instance has log_connections parameter enabled"
        );
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should PASS if no RDS DB instances found", function (done) {
      const cache = createCache([]);
      rdsLogConnectionEnabled.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include("No RDS DB instances found");
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should UNKNOWN if unable to query RDS DB instances", function (done) {
      const cache = createCache([], null, {
        err: "Unable to query RDS DB instances",
      });
      rdsLogConnectionEnabled.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(3);
        expect(results[0].message).to.include(
          "Unable to query RDS DB instances"
        );
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });

    it("should UNKNOWN if unable to query DB parameters", function (done) {
      const cache = createCache([describeDBInstances[0]], {}, null, {
        err: "Unable to query DB parameters",
      });
      rdsLogConnectionEnabled.run(cache, {}, (err, results) => {
        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(3);
        expect(results[0].message).to.include("Unable to query DB parameters");
        expect(results[0].region).to.equal("cn-hangzhou");
        done();
      });
    });
  });
});
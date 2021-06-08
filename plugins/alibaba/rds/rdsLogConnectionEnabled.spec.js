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
        }
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
        }
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
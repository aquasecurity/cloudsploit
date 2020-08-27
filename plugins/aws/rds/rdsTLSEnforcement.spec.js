var assert = require("assert");
var expect = require("chai").expect;
var rds = require("./rdsTLSEnforcement");

const createCache = (err, dbInstance, dbParameterGroups, dbParameters) => {
    return {
        rds: {
            describeDBInstances: {
                "us-east-1": {
                    err: err,
                    data: dbInstance
                }
            },
            describeDBParameterGroups:{
                "us-east-1": {
                    err: err,
                    data: dbParameterGroups
                }
            },
            describeDBParameters: {
                "us-east-1": dbParameters
            }
        }
    }
};

describe("rdsTLSEnforcement", function () {
    describe("run", function () {
        it("should give passing result if no RDS instances are found", function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include("No RDS Databases found")
                done()
            };

            const cache = createCache(
                null,
                []
            );

            rds.run(cache, {}, callback);
        });

        it("should give passing result when TLS RDS is enabled on both database", function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2)
                expect(results[0].status).to.equal(0)
                expect(results[1].status).to.equal(0)
                expect(results[0].message).to.include("TLS is enforced on the test01 database.")
                expect(results[1].message).to.include("TLS is enforced on the test02 database.")
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        DBInstanceIdentifier: "test01",
                        Engine: "mysql",
                        DBParameterGroups: [{DBParameterGroupName: "test01pgroup"}],
                    },
                    {
                        DBInstanceIdentifier: "test02",
                        Engine: "sqlserver-ex",
                        DBParameterGroups: [{DBParameterGroupName: "test02pgroup"}],
                    }],
                {DBParameterGroupName: [{
                            DBParameterGroupName: "test01pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.mysql"
                        },
                        {
                            DBParameterGroupName: "test02pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.mssql"
                        }]
                    },
                {
                    test01pgroup:{data: { Parameters: [{
                        ParameterName: "require_secure_transport", ParameterValue: "1"}]}, err: null,
                    },
                    test02pgroup:{data: { Parameters: [{
                        ParameterName: "rds.force_ssl", ParameterValue: "1"}]}, err: null
                    }
                }
            );

            rds.run(cache, {}, callback);
        });

        it("should give not passing result when TLS RDS is not enabled and when there are errors", function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(3)
                expect(results[0].status).to.equal(2)
                expect(results[1].status).to.equal(3)
                expect(results[2].status).to.equal(3)
                expect(results[0].message).to.include("TLS is not enforced on the test01 database.")
                expect(results[1].message).to.include("Unable to find Parameter: rds.force_ssl for test02 database.")
                expect(results[2].message).to.include("Unable to query for parameters on Parameter Group: test03pgroup.error")
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        DBInstanceIdentifier: "test01",
                        Engine: "mysql",
                        DBParameterGroups:[{DBParameterGroupName: "test01pgroup"}],
                    },
                    {
                        DBInstanceIdentifier: "test02",
                        Engine: "sqlserver-ex",
                        DBParameterGroups:[{DBParameterGroupName: "test02pgroup"}],
                    },
                    {
                        DBInstanceIdentifier: "test03",
                        Engine: "postgres",
                        DBParameterGroups:[{DBParameterGroupName: "test03pgroup"}],
                    }],
                {DBParameterGroupName: [
                        {
                            DBParameterGroupName: "test01pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.mysql"
                        },
                        {
                            DBParameterGroupName: "test02pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.mssql"
                        },
                        {
                            DBParameterGroupName: "test03pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.postgres"
                        }
                    ]},
                {
                    test01pgroup:{data: {Parameters:[{
                                ParameterName: "require_secure_transport"}]}, err: null,
                    },
                    test02pgroup:{data: {Parameters:[]}, err: null
                    },
                    test03pgroup:{data: {Parameters:[]}, err: "error"
                    }
                }
            );

                rds.run(cache, {}, callback);
            });

        it("should give not passing result when TLS RDS is not enabled on one parameter group", function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include("TLS is not enforced on the test01 database.")
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        DBInstanceIdentifier: "test01",
                        Engine: "mysql",
                        DBParameterGroups:[{DBParameterGroupName: "test01pgroup"}, {DBParameterGroupName: "test02pgroup"}],
                    }],
                {DBParameterGroupName: [
                        {
                            DBParameterGroupName: "test01pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.mysql"
                        },
                        {
                            DBParameterGroupName: "test02pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.mysql"
                        }]},
                {
                    test01pgroup:{data: {Parameters:[{
                                ParameterName: "require_secure_transport", ParameterValue: "1"}]}, err: null,
                    },
                    test02pgroup:{data: {
                            Parameters:[{ParameterName: "require_secure_transport", ParameterValue: "0"}]}, err: null
                    },
                }
            );

            rds.run(cache, {}, callback);
        });

        it("should give pass result if the database engine is not supported", function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].message).to.include("TLS Enforcement is not supported on the test01 database with oracle-se1 engine.")
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        DBInstanceIdentifier: "test01",
                        Engine: "oracle-se1",
                        DBParameterGroups:[{DBParameterGroupName: "test01pgroup"}, {DBParameterGroupName: "test02pgroup"}],
                    }],
                {DBParameterGroupName: [
                        {
                            DBParameterGroupName: "test01pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.oracle-se1"
                        },
                        {
                            DBParameterGroupName: "test02pgroup",
                            DBParameterGroupArn: "arn:aws:rds:us-east-1:null:pg:default.oracle-se1"
                        }]},
                {
                    test01pgroup:{data: {Parameters:[]}, err: null,
                    },
                    test02pgroup:{data: {Parameters:[]}, err: null
                    },
                }
            );

            rds.run(cache, {}, callback);
        });
    });
});

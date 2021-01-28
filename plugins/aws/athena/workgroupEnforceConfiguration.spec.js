var expect = require('chai').expect;
const workgroupEnforceConfiguration = require('./workgroupEnforceConfiguration');

const listWorkGroups = [
    {
        "Name": "primary",
        "State": "ENABLED",
        "Description": "",
        "CreationTime": 1597044190.575
    },
    {
        "Name": "wg-1",
        "State": "ENABLED",
        "Description": "Workgroup for test cases",
        "CreationTime": 1610126414.836
    },
    {
        "Name": "wg-2",
        "State": "ENABLED",
        "Description": "Workgroup for test cases",
        "CreationTime": 1610126414.836
    }
];

const getWorkGroup = [
    {
        "WorkGroup": {
            "Name": "wg-1",
            "State": "ENABLED",
            "Configuration": {
                "ResultConfiguration": {
                    "OutputLocation": "s3://aws-logs-000011112222-us-east-1/"
                },
                "EnforceWorkGroupConfiguration": false,
                "PublishCloudWatchMetricsEnabled": false,
                "RequesterPaysEnabled": false
            },
            "Description": "Workgroup for test cases",
            "CreationTime": 1610126414.836
        }
    },
    {
        "WorkGroup": {
            "Name": "wg-2",
            "State": "ENABLED",
            "Configuration": {
                "ResultConfiguration": {
                    "OutputLocation": "s3://aws-logs-000011112222-us-east-1/",
                    "EncryptionConfiguration": {
                        "EncryptionOption": "SSE_KMS",
                        "KmsKey": "arn:aws:kms:us-east-1:000011112222:key/7cb78370-cdc6-4ccb-a973-ecc8cbdc0dec"
                    }
                },
                "EnforceWorkGroupConfiguration": true,
                "PublishCloudWatchMetricsEnabled": false,
                "RequesterPaysEnabled": false
            },
            "Description": "encrypted workgroup",
            "CreationTime": 1610126849.952
        }
    },
    {
        "WorkGroup": {
            "Name": "primary",
            "State": "ENABLED",
            "Configuration": {
                "ResultConfiguration": {},
                "EnforceWorkGroupConfiguration": false,
                "PublishCloudWatchMetricsEnabled": false,
                "RequesterPaysEnabled": false
            },
            "CreationTime": 1597044190.575
        }
    }
];


const createCache = (workGroups, getWorkGroup, listErr, getErr) => {
    var wgName = (workGroups && workGroups.length) ? workGroups[0].Name : null;
    return {
        athena: {
            listWorkGroups: {
                'us-east-1': {
                    err: listErr,
                    data: workGroups
                },
            },
            getWorkGroup: {
                'us-east-1': {
                    [wgName]: {
                        err: getErr,
                        data: getWorkGroup
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        athena: {
            listWorkGroups: {
                'us-east-1': null,
            }
        }
    };
};

describe('workgroupEnforceConfiguration', function () {
    describe('run', function () {
        it('should PASS if Athena workgroup is enforcing configuration options', function (done) {
            const cache = createCache([listWorkGroups[2]], getWorkGroup[1]);
            workgroupEnforceConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Athena primary workgroup is not enforcing configuration options but is not in use', function (done) {
            const cache = createCache([listWorkGroups[0]], getWorkGroup[2]);
            workgroupEnforceConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Athena workgroup is not enforcing configuration options', function (done) {
            const cache = createCache([listWorkGroups[1]], getWorkGroup[0]);
            workgroupEnforceConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Athena workgroups found', function (done) {
            const cache = createCache([]);
            workgroupEnforceConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list Athena workgroups', function (done) {
            const cache = createCache(listWorkGroups, null, { message: 'Unable to list workgroups'});
            workgroupEnforceConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Athena workgroup', function (done) {
            const cache = createCache([listWorkGroups[0]], getWorkGroup, null, { message: 'Unable to describe Athena workgroup'});
            workgroupEnforceConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list workgroups response not found', function (done) {
            const cache = createNullCache();
            workgroupEnforceConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
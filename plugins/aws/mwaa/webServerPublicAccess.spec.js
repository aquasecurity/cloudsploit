const expect = require('chai').expect;
var webServerPublicAccess = require('./webServerPublicAccess');

const listEnvironments = [
    "env-1"
];

const getEnvironment = [
    {
        "Environment": {
            "Arn": "arn:aws:airflow:us-east-1:000111222333:environment/env-1",
            "ExecutionRoleArn": "arn:aws:iam::000111222333:role/service-role/AmazonMWAA-role-1",
            "Name": "env-1",
            "NetworkConfiguration": {
                "SecurityGroupIds": [
                    "sg-06bb33bc2a9d6cfa0",
                    "sg-0356a73d9749f97ad"
                ],
                "SubnetIds": [
                    "subnet-027b3e2dbd13be412",
                    "subnet-0ba3663b2ac3734d2"
                ]
            },
            "WebserverAccessMode": "PRIVATE_ONLY",
        }
    },
    {
        "Environment": {
            "Arn": "arn:aws:airflow:us-east-1:000111222333:environment/env-1",
            "ExecutionRoleArn": "arn:aws:iam::000111222333:role/service-role/AmazonMWAA-role-2",
            "Name": "env-1",
            "NetworkConfiguration": {
                "SecurityGroupIds": [
                    "sg-06bb33bc2a9d6cfa0",
                    "sg-0356a73d9749f97ad"
                ],
                "SubnetIds": [
                    "subnet-027b3e2dbd13be412",
                    "subnet-0ba3663b2ac3734d2"
                ]
            },
            "WebserverAccessMode": "PUBLIC_ONLY",
        }
    }
];

const createCache = (listEnvironments, getEnvironment, listErr, getErr) => {
    var envName = (listEnvironments && listEnvironments.length) ? listEnvironments[0] : null;
    return {
        mwaa: {
            listEnvironments: {
                'us-east-1': {
                    err: listErr,
                    data: listEnvironments
                }
            },
            getEnvironment: {
                'us-east-1': {
                    [envName]: {
                        err: getErr,
                        data: getEnvironment
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        mwaa: {
            listEnvironments: {
                'us-east-1': null
            }
        }
    };
};

describe('webServerPublicAccess', function () {
    describe('run', function () {

        it('should PASS if Apache Airflow UI can only be accessible from within the VPC', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[0]);
            webServerPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Apache Airflow UI can be accessed over the internet', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[1]);
            webServerPublicAccess.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Airflow environments found', function (done) {
            const cache = createCache([]);
            webServerPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Airflow environments', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[0], { message: 'error listing Airflow environments'});
            webServerPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to get Ariflow environment', function (done) {
            const cache = createCache(listEnvironments, getEnvironment[0], null, { message: 'error getting Airflow environment'});
            webServerPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list Airflow environments response not found', function (done) {
            const cache = createNullCache();
            webServerPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
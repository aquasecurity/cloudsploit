var expect = require('chai').expect;
var infraConfigNotificationEnabled = require('./infraConfigNotificationEnabled');

const listInfrastructureConfigurations = [
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:infrastructure-configuration/akhtar-conf",
        "name": "akhtar-conf",
        "dateCreated": "2022-03-08T10:51:11.222Z",
        "tags": {},
        "instanceProfileName": "AmazonSSMRoleForInstancesQuickSetup"
    },
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:infrastructure-configuration/sadeedinfra",
        "name": "sadeedinfra",
        "dateCreated": "2022-03-24T15:38:07.970Z",
        "tags": {},
        "instanceTypes": [
            "a1.2xlarge"
        ],
        "instanceProfileName": "AmazonSSMRoleForInstancesQuickSetup"
    }
];

const getInfrastructureConfiguration = [
    {
        "requestId": "d54c83f4-7d84-4fd2-b79d-88e8e7f20f5e",
        "infrastructureConfiguration": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:infrastructure-configuration/sadeedinfra",
            "name": "sadeedinfra",
            "instanceTypes": [
                "a1.2xlarge"
            ],
            "instanceProfileName": "AmazonSSMRoleForInstancesQuickSetup",
            "logging": {
                "s3Logs": {}
            },
            "terminateInstanceOnFailure": true,
            "snsTopicArn": "arn:aws:sns:us-east-1:000011112222:mine1",
            "dateCreated": "2022-03-24T15:38:07.970Z",
            "tags": {}
        }
    },
    {
        "requestId": "538dfa42-bcce-412e-9cb4-5abc1a1b5be0",
        "infrastructureConfiguration": {
            "arn": "arn:aws:imagebuilder:us-east-1:000011112222:infrastructure-configuration/akhtar-conf",
            "name": "akhtar-conf",
            "instanceProfileName": "AmazonSSMRoleForInstancesQuickSetup",
            "logging": {
                "s3Logs": {}
            },
            "terminateInstanceOnFailure": true,
            "dateCreated": "2022-03-08T10:51:11.222Z",
            "tags": {}
        }
    }
];


const createCache = (recipe, getInfrastructureConfiguration, recipeErr, getInfrastructureConfigurationErr) => {
    var recipeArn = (recipe && recipe.length) ? recipe[0].arn: null;
    return {
        imagebuilder: {
            listInfrastructureConfigurations: {
                'us-east-1': {
                    err: recipeErr,
                    data: recipe
                },
            },
            getInfrastructureConfiguration: {
                'us-east-1': {
                    [recipeArn]: {
                        data:getInfrastructureConfiguration,
                        err: getInfrastructureConfigurationErr
                    }
                }
            }
        },
    };
};

describe('infraConfigNotificationEnabled', function () {
    describe('run', function () {
        it('should FAIL if Infrastructure configuration does not have SNS notifications enabled', function (done) {
            const cache = createCache([listInfrastructureConfigurations[0]], getInfrastructureConfiguration[1]);
            infraConfigNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Infrastructure configuration does not have SNS notifications enabled');
                done();
            });
        });

        it('should PASS if Infrastructure configuration has SNS notifications enabled', function (done) {
            const cache = createCache([listInfrastructureConfigurations[1]], getInfrastructureConfiguration[0]);
            infraConfigNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Infrastructure configuration has SNS notifications enabled');
                done();
            });
        });

        it('should PASS if No list infrastructure configuration found', function (done) {
            const cache = createCache([]);
            infraConfigNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No list infrastructure configuration found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for infrastructure configuration summary List', function (done) {
            const cache = createCache(null, null, { message: "Unable to query for infrastructure configuration summary List" });
            infraConfigNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for infrastructure configuration summary List');
                done();
            });
        });
    });
})
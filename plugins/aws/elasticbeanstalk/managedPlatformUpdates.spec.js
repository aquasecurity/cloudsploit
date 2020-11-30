var expect = require('chai').expect;
var managedPlatformUpdates = require('./managedPlatformUpdates');

const environments = [
    {
        "EnvironmentName": "Akhtar681-env-2",
        "EnvironmentId": "e-bucuvmfa4a",     
        "ApplicationName": "akhtar-681",
        "VersionLabel": "Sample Application",
        "SolutionStackName": "64bit Amazon Linux 2 v3.1.0 running Python 3.7",
        "PlatformArn": "arn:aws:elasticbeanstalk:us-east-1::platform/Python 3.7 running on 64bit Amazon Linux 2/3.1.0",
        "EndpointURL": "54.167.147.57",
        "CNAME": "Akhtar681-env-2.eba-g3c99pdr.us-east-1.elasticbeanstalk.com",
        "DateCreated": "2020-08-22T17:02:36.060Z",
        "DateUpdated": "2020-08-22T17:05:59.178Z",
        "Status": "Ready",
        "AbortableOperationInProgress": false,
        "Health": "Green",
        "HealthStatus": "Ok",
        "Tier": {
          "Name": "WebServer",
          "Type": "Standard",
          "Version": "1.0"
        },
        "EnvironmentLinks": [],
        "EnvironmentArn": "arn:aws:elasticbeanstalk:us-east-1:123456654321:environment/akhtar-681/Akhtar681-env-2"
    },
    {
        "EnvironmentName": "Akhtar681-env-1",
        "EnvironmentId": "e-3bb85da33w",
        "ApplicationName": "akhtar-681",
        "VersionLabel": "Sample Application",
        "SolutionStackName": "64bit Amazon Linux 2 v3.1.0 running Python 3.7",
        "PlatformArn": "arn:aws:elasticbeanstalk:us-east-1::platform/Python 3.7 running on 64bit Amazon Linux 2/3.1.0",
        "EndpointURL": "54.92.177.151",
        "CNAME": "Akhtar681-env-1.eba-g3c99pdr.us-east-1.elasticbeanstalk.com",
        "DateCreated": "2020-08-22T16:08:13.720Z",
        "DateUpdated": "2020-08-22T16:52:06.836Z",
        "Status": "Ready",
        "AbortableOperationInProgress": false,
        "Health": "Green",
        "HealthStatus": "Ok",
        "Tier": {
          "Name": "WebServer",
          "Type": "Standard",
          "Version": "1.0"
        },
        "EnvironmentLinks": [],
        "EnvironmentArn": "arn:aws:elasticbeanstalk:us-east-1:123456654321:environment/akhtar-681/Akhtar681-env-1"
    }
];

const configurationSettings = [
    {
        SolutionStackName: '64bit Amazon Linux 2 v3.1.0 running Python 3.7',
        PlatformArn: 'arn:aws:elasticbeanstalk:us-east-1::platform/Python 3.7 running on 64bit Amazon Linux 2/3.1.0',
        ApplicationName: 'akhtar-681',
        EnvironmentName: 'Akhtar681-env-1',
        DeploymentStatus: 'deployed',
        DateCreated: '2020-08-22T16:08:12.000Z',
        DateUpdated: '2020-08-22T16:50:53.000Z',
        OptionSettings: [
            {
                Namespace: 'aws:elasticbeanstalk:managedactions',
                OptionName: 'ManagedActionsEnabled',
                Value: 'false'
            },
            {
                Namespace: 'aws:elasticbeanstalk:managedactions',
                OptionName: 'PreferredStartTime',
                Value: 'Sat:03:00'
            },
            {
                Namespace: 'aws:elasticbeanstalk:managedactions',
                OptionName: 'ServiceRoleForManagedUpdates',
                Value: 'arn:aws:iam::123456654321:role/aws-elasticbeanstalk-service-role'
            },
            {
                Namespace: 'aws:elasticbeanstalk:managedactions:platformupdate',
                OptionName: 'InstanceRefreshEnabled',
                Value: 'true'
            }
        ]
    },
    {
        SolutionStackName: '64bit Amazon Linux 2 v3.1.0 running Python 3.7',
        PlatformArn: 'arn:aws:elasticbeanstalk:us-east-1::platform/Python 3.7 running on 64bit Amazon Linux 2/3.1.0',
        ApplicationName: 'akhtar-681',
        EnvironmentName: 'Akhtar681-env-1',
        DeploymentStatus: 'deployed',
        DateCreated: '2020-08-22T16:08:12.000Z',
        DateUpdated: '2020-08-22T16:50:53.000Z',
        OptionSettings: [
            {
                Namespace: 'aws:elasticbeanstalk:managedactions',
                OptionName: 'ManagedActionsEnabled',
                Value: 'true'
            },
            {
                Namespace: 'aws:elasticbeanstalk:managedactions',
                OptionName: 'PreferredStartTime',
                Value: 'Sat:03:00'
            },
            {
                Namespace: 'aws:elasticbeanstalk:managedactions',
                OptionName: 'ServiceRoleForManagedUpdates',
                Value: 'arn:aws:iam::123456654321:role/aws-elasticbeanstalk-service-role'
            },
            {
                Namespace: 'aws:elasticbeanstalk:managedactions:platformupdate',
                OptionName: 'InstanceRefreshEnabled',
                Value: 'false'
            }
        ]
    }
];
  
const createCache = (environments, configurationSettings) => {
    if (environments.length) var environmentArn = environments[0].EnvironmentArn;
    return {
        elasticbeanstalk: {
            describeEnvironments: {
                'us-east-1': {
                    data: environments
                },
            },
            describeConfigurationSettings: {
                'us-east-1': {
                    [environmentArn]: {
                            data: {
                                ConfigurationSettings: configurationSettings
                            }
                    }
                },
            },
        },
    };
};


const createErrorCache = () => {
    return {
        elasticbeanstalk: {
            describeEnvironments: {
                'us-east-1': {
                    err: {
                        message: 'error describing environments'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        elasticbeanstalk: {
            describeEnvironments: {
                'us-east-1': null,
            },
        },
    };
};

describe('managedPlatformUpdates', function () {
    describe('run', function () {

        it('should PASS if unable to get application environments', function (done) {
            const cache = createCache([]);
            managedPlatformUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if unable to get configuration settings', function (done) {
            const cache = createCache([environments[0]],[]);
            managedPlatformUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if managed platform updates are not enabled for application environment', function (done) {
            const cache = createCache([environments[0]], [configurationSettings[0]]);
            managedPlatformUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if managed platform updates are enabled for application environment', function (done) {
            const cache = createCache([environments[1]], [configurationSettings[1]]);
            managedPlatformUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if unable to get environments', function (done) {
            const cache = createNullCache();
            managedPlatformUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error occurs while fetching environments', function (done) {
            const cache = createErrorCache();
            managedPlatformUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
var expect = require('chai').expect;
var sqlServerTLSVersion = require('./sqlServerTLSVersion.js');

const parameterGroups = [
    {
        "DBParameterGroupName": "default.sqlserver-ex-14.0",
        "DBParameterGroupFamily": "sqlserver-ex-14.0",
        "Description": "Default parameter group for sqlserver-ex-14.0",
        "DBParameterGroupArn": "arn:aws:rds:us-east-1:23424531345:pg:default.sqlserver-ex-14.0"
    },
    {
        "DBParameterGroupName": "ex-g",
        "DBParameterGroupFamily": "sqlserver-ex-14.0",
        "Description": "abv",
        "DBParameterGroupArn": "arn:aws:rds:us-east-1:23424531345:pg:ex-g"
    }
];

const groupParameters = [
    [
        {
            ParameterName: 'rds.tls10',
            ParameterValue: 'disabled',
            Description: 'TLS 1.0.',
            Source: 'user',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.tls11',
            ParameterValue: 'default',
            Description: 'TLS 1.1.',
            Source: 'user',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.tls12',
            ParameterValue: 'default',
            Description: 'TLS 1.2.',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: false,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        }
    ],
    [
        {
            ParameterName: 'rds.tls10',
            ParameterValue: 'disabled',
            Description: 'TLS 1.0.',
            Source: 'user',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.tls11',
            ParameterValue: 'disabled',
            Description: 'TLS 1.1.',
            Source: 'user',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: true,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        },
        {
            ParameterName: 'rds.tls12',
            ParameterValue: 'default',
            Description: 'TLS 1.2.',
            Source: 'system',
            ApplyType: 'static',
            DataType: 'string',
            AllowedValues: 'default, enabled, disabled',
            IsModifiable: false,
            ApplyMethod: 'pending-reboot',
            SupportedEngineModes: []
        }
    ]
];

const createCache = (parameterGroups, groupParameters) => {
    if (parameterGroups.length) var dbParameterGroupName = parameterGroups[0]['DBParameterGroupName'];
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': {
                    data: parameterGroups
                },
            },
            describeDBParameters: {
                'us-east-1': {
                    [dbParameterGroupName]: {
                            data: {
                                Parameters: groupParameters
                            }
                    }
                },
            },
        },
    };
};


const createErrorCache = () => {
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing parameter groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBParameterGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('sqlServerTLSVersion', function () {
    describe('run', function () {

        it('should PASS if unable to get parameter groups', function (done) {
            const cache = createCache([]);
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if unable to get group parameters', function (done) {
            const cache = createCache([parameterGroups[0]],[]);
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if parameter group does not use TLS version 1.2', function (done) {
            const cache = createCache([parameterGroups[0]], groupParameters[0]);
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if parameter group uses TLS version 1.2', function (done) {
            const cache = createCache([parameterGroups[1]], groupParameters[1]);
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if unable to get parameter groups', function (done) {
            const cache = createNullCache();
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error occurs while fetching parameter groups', function (done) {
            const cache = createErrorCache();
            sqlServerTLSVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
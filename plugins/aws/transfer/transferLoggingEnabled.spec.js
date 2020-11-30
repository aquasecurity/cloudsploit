var expect = require('chai').expect;
var transferLoggingEnabled = require('./transferLoggingEnabled');

const listServers = [
    {
        "Arn": "arn:aws:transfer:us-east-1:112233445566:server/s-c19caf494fe6450cb",
        "IdentityProviderType": "SERVICE_MANAGED",
        "EndpointType": "PUBLIC",
        "LoggingRole": "arn:aws:iam::112233445566:role/service-role/testing-123-role-7t7oo29b",
        "ServerId": "s-c19caf494fe6450cb",
        "State": "ONLINE",
        "UserCount": 0
    },
    {
        "Arn": "arn:aws:transfer:us-east-1:112233445566:server/s-uyg23g3be231jb2",
        "IdentityProviderType": "SERVICE_MANAGED",
        "EndpointType": "PUBLIC",
        "ServerId": "s-uyg23g3be231jb2",
        "State": "ONLINE",
        "UserCount": 0
    }
];

const createCache = (servers) => {
    return {
        transfer: {
            listServers: {
                'us-east-1': {
                    data: servers
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        transfer: {
            listServers: {
                'us-east-1': {
                    err: {
                        message: 'Error listing transfer servers'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        transfer: {
            listServers: {
                'us-east-1': {
                    data: null
                }
            }
        }
    };
};

describe('transferLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if logging role is properly configured for Transfer server', function (done) {
            const cache = createCache([listServers[0]]);
            transferLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if logging role is not properly configured for Transfer server', function (done) {
            const cache = createCache([listServers[1]]);
            transferLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Transfer servers found', function (done) {
            const cache = createCache([]);
            transferLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should unknown if unable to list Transfer servers', function (done) {
            const cache = createErrorCache();
            transferLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Transfer servers response not found', function (done) {
            const cache = createNullCache();
            transferLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                done();
            });
        });
    });
});

var expect = require('chai').expect;
var transferPrivateLinkInUse = require('./transferPrivateLinkInUse');

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
        "EndpointType": "VPC-ENDPOINT",
        "ServerId": "s-uyg23g3be231jb2",
        "State": "ONLINE",
        "UserCount": 0
    },
    {
        "Arn": "arn:aws:transfer:us-east-1:112233445566:server/s-uyg23g3be231jb2",
        "IdentityProviderType": "SERVICE_MANAGED",
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

describe('transferPrivateLinkInUse', function () {
    describe('run', function () {
        it('should PASS if PrivateLink endpoints are used by server', function (done) {
            const cache = createCache([listServers[1]]);
            transferPrivateLinkInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Public endpoints are used by server', function (done) {
            const cache = createCache([listServers[0]]);
            transferPrivateLinkInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if EndpointType property is not found in response', function (done) {
            const cache = createCache([listServers[2]]);
            transferPrivateLinkInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Transfer servers found', function (done) {
            const cache = createCache([]);
            transferPrivateLinkInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should unknown if unable to list Transfer servers', function (done) {
            const cache = createErrorCache();
            transferPrivateLinkInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list Transfer servers response not found', function (done) {
            const cache = createNullCache();
            transferPrivateLinkInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                done();
            });
        });
    });
});

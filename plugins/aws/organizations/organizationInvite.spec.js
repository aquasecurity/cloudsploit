var expect = require('chai').expect;
var organizationInvite = require('./organizationInvite')

const createCache = (handshake) => {
    return {
        organizations: {
            listHandshakesForAccount: {
                'us-east-1': {
                    data: [handshake],
                },
            },
        },
    };
};

const createErrorCache = (code) => {
    return {
        organizations: {
            listHandshakesForAccount: {
                'us-east-1': {
                    err: {
                        code,
                    },
                },
            },
        },
    };
};

describe.only('organizationInvite', function () {
    describe('run', function () {
        it('should FAIL when there is an OPEN INVITE handshake', function (done) {
            const cache = createCache({
                State: 'OPEN',
                Action: 'INVITE',
            });

            organizationInvite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS when all features enabled', function (done) {
            const cache = createCache({
                State: 'DECLINED',
                Action: 'INVITE',
            });

            organizationInvite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should UNKNOWN if there was an unexpected error describing organization', function (done) {
            const cache = createErrorCache('ClientError')

            organizationInvite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });
    });
});

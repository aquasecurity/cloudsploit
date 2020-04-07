var expect = require('chai').expect;
var organizationInvite = require('./organizationInvite')

const createCache = (handshakes) => {
    return {
        organizations: {
            listHandshakesForAccount: {
                'us-east-1': {
                    data: handshakes,
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

describe('organizationInvite', function () {
    describe('run', function () {
        it('should FAIL when there is an OPEN INVITE handshake', function (done) {
            const cache = createCache([
                {
                    State: 'OPEN',
                    Action: 'INVITE',
                    Arn: 'arn:aws:organizations::111111111111:handshake/o-exampleorgid/invite/h-examplehandshakeid111'
                },{
                    State: 'OPEN',
                    Action: 'INVITE',
                    Arn: 'arn:aws:organizations::222222222222:handshake/o-exampleorgid/invite/h-examplehandshakeid222'
                }
            ]);

            organizationInvite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2, 'bad status');
                expect(results[1].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS when there are no open invites', function (done) {
            const cache = createCache([{
                State: 'DECLINED',
                Action: 'INVITE',
                Arn: 'arn:aws:organizations::111111111111:handshake/o-exampleorgid/invite/h-examplehandshakeid111'
            }]);

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

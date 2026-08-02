const expect = require('chai').expect;
var securityHubEnabled = require('./securityHubEnabled.js')

const describeHub = {
    HubArn: 'arn:aws:securityhub:us-east-1:000011112222:hub/default',
    SubscribedAt: '2023-08-01T12:46:59.711Z',
    AutoEnableControls: true,
    ControlFindingGenerator: 'SECURITY_CONTROL',
};



const createCache = (describeHubData, describeHubErr) => {
    return {
        securityhub: {
            describeHub: {
                'us-east-1': {
                    err: describeHubErr,
                    data: describeHubData,
                },
            },
        },
    };
};



describe('securityHubEnabled', function () {
    describe('run', function () {
        it('should PASS if Security Hub is enabled', function (done) {
            const cache = createCache(describeHub, null);
            securityHubEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.equal('Security Hub is enabled');
                done();
            });
        });

        it('should FAIL if Security Hub is not enabled', function (done) {
            const errorMessage = 'InvalidAccessException';
            const cache = createCache(describeHub, { name: 'InvalidAccessException' });
            securityHubEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.equal('Security Hub is not enabled');
                done();
            });
        });

        it('should return UNKNOWN if Unable to query for Security Hub', function (done) {
            const errorMessage = 'Unable to query for Security Hub';
            const cache = createCache(describeHub, errorMessage);
            securityHubEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});

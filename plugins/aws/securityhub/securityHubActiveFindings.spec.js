const expect = require('chai').expect;
var securityHubActiveFindings = require('./securityHubActiveFindings.js')
var failDate = new Date();
failDate.setMonth(failDate.getMonth() - 1);

const describeHub = {
    HubArn: 'arn:aws:securityhub:us-east-1:000011112222:hub/default',
    SubscribedAt: '2023-08-01T12:46:59.711Z',
    AutoEnableControls: true,
    ControlFindingGenerator: 'SECURITY_CONTROL',
};

const getFindings = [
    {
        'AwsAccountId':'123456',
        'CompanyName':'AWS',
        'CreatedAt': new Date(),
        'Description': 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables.',
    },
    {
        'AwsAccountId':'123456',
        'CompanyName':'AWS',
        'CreatedAt': failDate,
        'Description': 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables.',
    },
    {
        'AwsAccountId':'123456',
        'CompanyName':'AWS',
        'CreatedAt': new Date(),
        'Description': 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables.',
    }
]


const createCache = (describeHubData, describeHubErr, getFindings, getFindingErr) => {
    return {
        securityhub: {
            describeHub: {
                'us-east-1': {
                    err: describeHubErr,
                    data: describeHubData,
                },
            },
            getFindings: {
                'us-east-1': {
                    err: getFindingErr,
                    data: getFindings,
                },
            }
        },
    };
};



describe('securityHubActiveFindings', function () {
    describe('run', function () {

        it('should PASS if Security Hub is not enabled', function (done) {
            const errorMessage = 'InvalidAccessException';
            const cache = createCache(describeHub, { code: 'InvalidAccessException' });
            securityHubActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.equal('Security Hub is not enabled');
                done();
            });
        });

        it('should return UNKNOWN if Unable to query for Security Hub', function (done) {
            const errorMessage = 'Unable to query for Security Hub';
            const cache = createCache(describeHub, errorMessage);
            securityHubActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if Security Hub has no active findings', function (done) {
            const cache = createCache(describeHub, null, []);
            securityHubActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.equal('No active findings available');
                done();
            });
        });

        it('should PASS if Security Hub has zero active findings', function (done) {
            const cache = createCache(describeHub, null, [getFindings[0]]);
            securityHubActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.equal('Security Hub has no active findings');
                done();
            });
        });

        it('should FAIL if Security Hub has  active findings', function (done) {
            const cache = createCache(describeHub, null, [getFindings[1]]);
            securityHubActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.includes('Security Hub has over');
                done();
            });
        });
    });
});

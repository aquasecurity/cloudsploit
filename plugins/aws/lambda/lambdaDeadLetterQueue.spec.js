const expect = require('chai').expect;
const lambdaDeadLetterQueue = require('./lambdaDeadLetterQueue');

// Mock data
const lambdaFunctions = [
    {
        FunctionName: 'testFunction1',
        DeadLetterConfig: {
            TargetArn: 'arn:aws:sqs:us-east-1:123456789012:dead-letter-queue'
        }
    },
    {
        FunctionName: 'testFunction2',
        DeadLetterConfig: null
    }
];

const createCache = (lambdaFunctions, lambdaFunctionsErr) => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: lambdaFunctionsErr,
                    data: lambdaFunctions
                }
            }
        }
    };
};

describe('lambdaDeadLetterQueue', function () {
    describe('run', function () {

        it('should PASS if Lambda function has Dead Letter Queue configured', function (done) {
            const cache = createCache(lambdaFunctions[0], null);
            lambdaDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Lambda function does not have Dead Letter Queue configured', function (done) {
            const cache = createCache([lambdaFunctions[1]], null); // Only the second function doesn't have a Dead Letter Queue
            lambdaDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to list Lambda functions', function (done) {
            const cache = createCache(null, { message: 'Unable to list functions' });
            lambdaDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no Lambda functions found', function (done) {
            const cache = createCache([], null);
            lambdaDeadLetterQueue.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});

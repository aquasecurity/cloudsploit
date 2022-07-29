var expect = require('chai').expect;
const ssmSessionDuration = require('./ssmSessionDuration');

const describeSessions = [
    {
        "SessionId": "test-0cc5ea893bcf25c12",
        "Target": "i-0cabb616c72195cec",
        "Status": "Connected",
        "StartDate": new Date(Math.abs(new Date() - 30 * 60000)),
        "Owner": "arn:aws:iam::111222333444:user/test",
        "Details": "",
        "OutputUrl": {
            "S3OutputUrl": "",
            "CloudWatchOutputUrl": ""
        },
        "MaxSessionDuration": "20"
    },
    {
        "SessionId": "test-0cc5ea893bcf25c12",
        "Target": "i-0cabb616c72195cec",
        "Status": "Connected",
        "StartDate": new Date(Math.abs(new Date() - 30 * 60000)),
        "Owner": "arn:aws:iam::111222333444:user/test",
        "Details": "",
        "OutputUrl": {
            "S3OutputUrl": "",
            "CloudWatchOutputUrl": ""
        },
        "MaxSessionDuration": "50"
    },
    {
        "SessionId": "test-0cc5ea893bcf25c12",
        "Target": "i-0cabb616c72195cec",
        "Status": "Connected",
        "StartDate": new Date(Math.abs(new Date() - 30 * 60000)),
        "Owner": "arn:aws:iam::111222333444:user/test",
        "Details": "",
        "OutputUrl": {
            "S3OutputUrl": "",
            "CloudWatchOutputUrl": ""
        },
        "MaxSessionDuration": "50"
    },
    {
        "SessionId": "test-0cc5ea893bcf25c15",
        "Target": "i-0cabb616c72195cec",
        "Status": "Connected",
        "StartDate": new Date(Math.abs(new Date() - 20 * 60000)),
        "Owner": "arn:aws:iam::111222333444:user/test",
        "Details": "",
        "OutputUrl": {
            "S3OutputUrl": "",
            "CloudWatchOutputUrl": ""
        }
    },
];

const createCache = (sessions) => {
    return {
        ssm: {
            describeSessions: {
                'us-east-1': {
                    data: sessions
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ssm: {
            describeSessions: {
                'us-east-1': {
                    err: {
                        message: 'error describing instance information'
                    },
                }
            }
        }
    };
};

describe('ssmSessionDuration', function () {
    describe('run', function () {
        it('should PASS if there are no active sessions under SSM Session Manager', function (done) {
            const cache = createCache([]);
            ssmSessionDuration.run(cache, { ssm_session_max_duration: '40' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if the session`s active time is within the max time limit set in SSM Session Manager', function (done) {
            const cache = createCache([describeSessions[1]]);
            ssmSessionDuration.run(cache, { ssm_session_max_duration: '40' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if the session`s active time is greater than the max time limit set in SSM Session Manager', function (done) {
            const cache = createCache([describeSessions[0]]);
            ssmSessionDuration.run(cache, { ssm_session_max_duration: '20' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if error while fetching active sessions', function (done) {
            const cache = createErrorCache();
            ssmSessionDuration.run(cache, { ssm_session_max_duration: '40' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});

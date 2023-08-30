var expect = require('chai').expect;
var moment = require('moment');
var lastInspectorRun = require('./lastInspectorRun');

const listAssessmentTemplates = [
    "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-OXqJxJvw",
    "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-VnJ4HhPd"
];

const listAssessmentRuns = {
    "assessmentRunArns": [
        "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-OXqJxJvw/run/0-M8S8FW0L",
        "arn:aws:inspector:us-east-1:123456789012:target/0-nvg8Tm4A/template/0-VnJ4HhPd/run/0-x45KIf3j"
    ]
};
const describeAssessmentRuns = {

    "assessmentRuns": [
        {
            "completedAt": "2023-08-20T14:30:00Z"
        },
        {
            "completedAt": "2023-08-18T09:15:00Z"
        }
    ]
};

const createCache = (assessmentTemplates, assessmentRuns) => {
    return {
        inspector: {
            listAssessmentTemplates: {
                'us-east-1': {
                    data: assessmentTemplates
                }
            },
            listAssessmentRuns: {
                'us-east-1': {
                    [assessmentTemplates[0]]: {
                        data: assessmentRuns
                    },
                    [assessmentTemplates[1]]: {
                        data: assessmentRuns
                    }
                }
            },
            describeAssessmentRuns: {
                'us-east-1': {
                    [assessmentRuns.assessmentRunArns[0]]: {
                        data: describeAssessmentRuns
                    },
                    [assessmentRuns.assessmentRunArns[1]]: {
                        data: describeAssessmentRuns
                    }
                }
            }
        }
    };
};

describe('lastInspectorRun', function () {
    describe('run', function () {
        it('should PASS if assessment template run within the last 7 days', function (done) {
            const cache = createCache(listAssessmentTemplates, listAssessmentRuns);
            describeAssessmentRuns.assessmentRuns[0].completedAt = moment().subtract(3, 'days').toISOString();
            lastInspectorRun.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Assessment template run within the last 7 days');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if assessment template not run in the last 7 days', function (done) {
            const cache = createCache(listAssessmentTemplates, listAssessmentRuns);
            describeAssessmentRuns.assessmentRuns[0].completedAt = moment().subtract(8, 'days').toISOString();
            lastInspectorRun.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Assessment template not run in the last 7 days');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if there are no assessment templates', function (done) {
            const cache = createCache([], listAssessmentRuns);
            lastInspectorRun.run(cache, {}, (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no assessment runs', function (done) {
            const cache = createCache(listAssessmentTemplates, { assessmentRunArns: [] });
            lastInspectorRun.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should PASS if assessment template run on the exact 7th day', function (done) {
            const cache = createCache(listAssessmentTemplates, listAssessmentRuns);
            describeAssessmentRuns.assessmentRuns[0].completedAt = moment().subtract(7, 'days').toISOString();
            lastInspectorRun.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });


    });
});







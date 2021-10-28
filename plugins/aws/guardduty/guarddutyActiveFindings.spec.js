var expect = require('chai').expect;
var guardDutyActiveFindings = require('./guarddutyActiveFindings');

const getDetectors = [
    {
        Status: 'ENABLED',
        FindingPublishingFrequency: 'SIX_HOURS'
    },
    {
        Status: 'DISABLED',
        FindingPublishingFrequency: 'SIX_HOURS'
    }

];

const getFindings = [
    {
        Findings: [
            {
                "Severity": 7.0,
            }
        ]
    },
    {
        Findings: [
            {
                "Severity": 2.0,
            },
        ]
    }
];

const listDetectors = [
    '564dfv789asfsfe36sdf89'
]

const listFindings = [
    {
        FindingIds: ['9654asdf78524werr634rtg'],
        NextToken: ''
    }
]

const createCache = (listDetectors, listFindings, getDetector, getFindings) => {
    const detectorId = (listDetectors.length, listDetectors[0]) ? listDetectors[0]: null;
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': {
                    data: listDetectors,
                },
            },
            listFindings: {
                'us-east-1': {
                    [detectorId]: {
                        data: listFindings,
                    }
                },
            },
            getDetector: {
                'us-east-1': {
                    [detectorId]: {
                        data: getDetector,
                    }
                },
            },
            getFindings: {
                'us-east-1': {
                    [detectorId]: {
                        data: getFindings,
                    }
                },
            },
        }
    }
};

const createErrorCache = (listDetectors, listFindings, getDetector, getFindings) => {
    const detectorId = (listDetectors.length, listDetectors[0]) ? listDetectors[0]: null;
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': {
                    data: listDetectors,
                    err: 'Unable to list detectors'
                },
            },
            listFindings: {
                'us-east-1': {
                    [detectorId]: {
                        data: listFindings,
                        err: 'Unable to list findings'
                    }
                },
            },
            getDetector: {
                'us-east-1': {
                    [detectorId]: {
                        data: getDetector,
                        err: 'Unable to get detectors'
                    }
                },
            },
            getFindings: {
                'us-east-1': {
                    [detectorId]: {
                        data: getFindings,
                        err: 'Unable to get findings'
                    }
                },
            },
        }
    }
} 

const createNullCache = () => {
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': null
            },
            listFindings: {
                'us-east-1': null
            },
            getDetector: {
                'us-east-1': null
            },
            getFindings: {
                'us-east-1': null
            },
        }
    }
} 
describe('guardDutyActiveFindings', function () {
    describe('run', function () {
        it('should PASS if detector is enabled and severity is not high', done => {
            const cache = createCache([listDetectors[0]], listFindings[0], getDetectors[0], getFindings[1]);
            guardDutyActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('High severity findings not found');
                done();
            });
        });

        it('should PASS if no Findings property not found', done => {
            const cache = createCache([listDetectors[0]], listFindings[0], getDetectors[0], {});
            guardDutyActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('No findings available');
                done();
            });
        });

        it('should FAIL if detector is disabled', done => {
            const cache = createCache([listDetectors[0]], listFindings[0], getDetectors[1], getFindings[1]);
            guardDutyActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.equal('GuardDuty detector is disabled');
                done();
            });
        });

        it('should FAIL if detector is enabled and severity is high', done => {
            const cache = createCache([listDetectors[0]], listFindings[0], getDetectors[0], getFindings[0]);
            guardDutyActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.equal('High severity findings found');
                done();
            });
        });

        it('should FAIL if GuardDuty detectors are not found', done => {
            const cache = createCache([], listFindings[0], getDetectors[0], getFindings[0]);
            guardDutyActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.equal('No GuardDuty detectors found');
                done();
            });
        });

        it('should UNKNOWN if unable to list detectors', done => {
            const cache = createErrorCache([], listFindings[0], getDetectors[0], getFindings[1]);
            guardDutyActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if no response received', done => {
            const cache = createNullCache();
            guardDutyActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
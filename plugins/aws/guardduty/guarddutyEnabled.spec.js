var assert = require('assert');
var expect = require('chai').expect;
var guarddutyEnabled = require('./guarddutyEnabled')

describe('guarddutyEnabled', function () {
    describe('run', function () {
        it('should FAIL when guard duty is not enabled', function () {
            const settings = {};
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: [],
                        },
                    },
                },
            };
            guarddutyEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
            });
        });

        it('should PASS when guard duty is enabled', function () {
            const settings = {};
            const cache = {
                guardduty: {
                    listDetectors: {
                        'us-east-1': {
                            data: ['id123'],
                        },
                    },
                },
            };
            guarddutyEnabled.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
            });
        });
    });
});

var expect = require('chai').expect;
var checkAdvisorRecommendations = require('./checkAdvisorRecommendations');

const recommendationsList = [
    {
        "category": "HighAvailability",
        "extendedProperties": {
            "assessmentKey": "abcd1234-abcd-1234-abcd-abcd1234abcd",
            "score": "50"
        },
        "id": "/subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd/providers/Microsoft.Advisor/recommendations/abcdabcd-abcd-abcd-abcd-abcdabcdabcd",
        "impact": "High",
        "impactedField": "Microsoft.Subscriptions/subscriptions",
        "impactedValue": "abcdabcd-1234-abcd-1234-abcdabcdabcd",
        "lastUpdated": "2020-06-02T15:10:46.164346+00:00",
        "metadata": null,
        "name": "abcdabcd-abcd-abcd-abcd-abcdabcdabcd",
        "recommendationTypeId": "abcd1234-abcd-1234-abcd-abcd1234abcd",
        "risk": null,
        "shortDescription": {
            "problem": "Enable Soft Delete",
            "solution": "Use soft delete on your Azure Storage Account to save and recover data after accidental overwrite or deletion"
        },
        "suppressionIds": null,
        "type": "Microsoft.Advisor/recommendations"
    },
];

const createCache = (err, recommendationsList) => {
    return {
        advisor: {
            recommendationsList: {
                'global': {
                    data: recommendationsList
                }
            }
        }
    }
};

describe('checkAdvisorRecommendations', function() {
    describe('run', function() {
        it('should give passing result if no Advisor Recommendations are found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No Advisor Recommendations found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(null, []);
            checkAdvisorRecommendations.run(cache, {}, callback);
        });

        it('should give failing result if Advisor Recommendations found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Advisor Recommendations found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(null, recommendationsList);
            checkAdvisorRecommendations.run(cache, {}, callback);
        });

        it('should give UNKNOWN result if unable to queyr for Advisor Recommendations', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for Advisor Recommendations')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(null);
            checkAdvisorRecommendations.run(cache, {}, callback);
        });
    })
})
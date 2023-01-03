var expect = require('chai').expect;
var plugin = require('./essentialContactsConfigured');

const createCache = (err, data) => {
    return {
        organizations: {
            list: {
                'global': {
                    data: [
                        {
                            "organizationId": "123456",
                            "displayName": "myorg",
                            "creationTime": "2018-03-03T17:56:10.122Z",
                            "lifecycleState": "ACTIVE",
                            "name": "organizations/123456"
                        }
                    ],
                    err: null
                }
            },
            essentialContacts: {
                'global': {
                    err: err,
                    data: data
                }
            },
        },
    }
};

describe('essentialContactsConfigured', function () {
    describe('run', function () {

        it('should give unknow if an error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query essential contacts for organization');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                'error',
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if essential contacts is configured for organization', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is configured');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "contacts": [
                          {
                            "name": "organizations/123456/contacts/0",
                            "email": "mycontact@gmail.com",
                            "notificationCategorySubscriptions": [
                              "SECURITY"
                            ],
                            "languageTag": "en-US",
                            "validationState": "VALID",
                            "validateTime": "2022-12-10T10:46:33.694820Z"
                          }
                        ]
                    } 
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if essential contacts is not configured for organization', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not configured');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                {}
            );

            plugin.run(cache, {}, callback);
        })

    })
});
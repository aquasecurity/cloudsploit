var expect = require('chai').expect;
var plugin = require('./defaultTagsForResources');

const defaultTagsList = [
    {
        value: '${iam.principal.name}',
        tagNamespaceId: 'namespace-1',
        tagDefinitionId: 'tag-1',
        tagDefinitionName: 'CreatedBy',
        isRequired: false,
        id: 'tag-1',
        compartmentId: 'compartment-1',
        timeCreated: '2022-01-04T16:42:07.246Z',
        lifecycleState: 'ACTIVE'
      },
      {
        value: '${oci.datetime}',
        tagNamespaceId: 'namespace-1',
        tagDefinitionId: 'tag-1',
        tagDefinitionName: 'CreatedOn',
        isRequired: false,
        id: 'tag-1',
        compartmentId: 'compartment-1',
        timeCreated: '2022-01-04T16:42:07.561Z',
        lifecycleState: 'ACTIVE'
      }
];

const createCache = (err, data) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        defaultTags: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('defaultTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to query for default tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for default tags')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                {err: 'error'},
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if no default tags found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('No default tags found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if compartment does not have default tags for resources', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('is not using')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [defaultTagsList[1]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if comaprtment has default tags for resources enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('is using')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [defaultTagsList[0]]
            );

            plugin.run(cache, {}, callback);
        });

    });
});
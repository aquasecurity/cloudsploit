var expect = require('chai').expect;
var plugin = require('./triggerHasTags');

const triggers = [
    {
        id: '11111',
        createTime: '2023-02-28T06:52:35.542711825Z',
        github: {
          push: { branch: '^master$' },
          owner: 'test-user',
          name: 'my-repo'
        },
        autodetect: true,
        name: 'trigger-us',
        resourceName: 'projects/test-proj/locations/us-central1/triggers/11111',
        tags: ['test']
      },
      {
        id: '22222',
        createTime: '2023-02-28T06:27:53.476869805Z',
        filename: 'cloudbuild.yaml',
        github: {
          pullRequest: { branch: '^master$', commentControl: 'COMMENTS_ENABLED' },
          owner: 'test-user',
          name: 'my-repo'
        },
        name: 'trigger-1',
        approvalConfig: { approvalRequired: true },
        resourceName: 'projects/test-proj/locations/global/triggers/22222'
      }
];

const createCache = (err, data) => {
    return {
        cloudbuild: {
            triggers: {
                 'global': {
                        err: err,
                        data: data
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};

describe('triggerHasTags', function () {
    describe('run', function () {
        it('should give unknown result if a trigger error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Cloud Build triggers');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no triggers are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Cloud Build triggers found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if cloud build trigger has tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('tags found for Cloud Build trigger');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [triggers[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if cloud build trigger does not have any tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have any tags');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [triggers[1]]
            );

            plugin.run(cache, {}, callback);
        })

    })
})
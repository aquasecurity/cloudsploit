var expect = require('chai').expect;
var plugin = require('./commentControlEnabled');

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
        resourceName: 'projects/test-proj/locations/us-central1/triggers/11111'
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
      },
      {
        id: '3333',
        createTime: '2023-02-28T06:28:25.992664063Z',
        github: {
          pullRequest: { branch: '^master$' },
          owner: 'test-user',
          name: 'my-repo'
        },
        autodetect: true,
        name: 'trigger-2',
        resourceName: 'projects/test-proj/locations/global/triggers/3333'
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

describe('commentControlEnabled', function () {
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

        it('should give passing result if cloud build trigger has comment control enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has comment control enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [triggers[1]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if cloud build trigger does not have comment control enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have comment control enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [triggers[2]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if cloud build trigger is not a pull request trigger', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is not a pull request trigger');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [triggers[0]]
            );

            plugin.run(cache, {}, callback);
        });
    })
})
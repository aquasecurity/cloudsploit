var expect = require('chai').expect;
const codebuildValidSourceProviders = require('./codebuildValidSourceProviders');

const listProjects = [
    'test-project'
];


const batchGetProjects ={
    "projects": [
        {
            "name": "test-project",
            "arn": "arn:aws:codebuild:us-east-1:111122223333:project/test-project",
            "source": {
                "type": "GITHUB",
                "location": "https://github.com/cloudsplit/scans",
                "gitCloneDepth": 1,
                "gitSubmodulesConfig": {
                    "fetchSubmodules": false
                },
                "reportBuildStatus": false,
                "insecureSsl": false
            },
            "secondarySources": [
                {
                    "type": "S3",
                    "location": "my-aqua-bucket/data",
                    "insecureSsl": false,
                    "sourceIdentifier": "s3_source"
                }
            ]
        }
    ],
};

const createCache = (listProjects, batchGetProjects, listProjectsErr, batchGetProjectsErr) => {
    let project = (listProjects && listProjects.length) ? listProjects[0] : null;
    return {
        codebuild: {
            listProjects: {
                'us-east-1': {
                    data: listProjects,
                    err: listProjectsErr
                }
            },
            batchGetProjects: {
                'us-east-1': {
                    [project]: {
                        data: batchGetProjects,
                        err: batchGetProjectsErr
                    }
                }
            }
        }
    }
};

const createNullCache = () => {
    return {
        codebuild: {
            listProjects: {
                'us-east-1': null,
            },
        },
    };
};

describe('codebuildValidSourceProviders', function () {
    describe('run', function () {
        it('should PASS if CodeBuild project is using allowed source providers', function (done) {
            const cache = createCache(listProjects, batchGetProjects);
            codebuildValidSourceProviders.run(cache, { codebuild_disallowed_source_providers: 'bitbucket'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CodeBuild project is using disallowed source providers', function (done) {
            const cache = createCache(listProjects, batchGetProjects);
            codebuildValidSourceProviders.run(cache, { codebuild_disallowed_source_providers: 's3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no CodeBuild projects found', function (done) {
            const cache = createCache([]);
            codebuildValidSourceProviders.run(cache, { codebuild_disallowed_source_providers: 's3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query CodeBuild projects', function (done) {
            const cache = createCache(listProjects, { message: 'Unable to query CodeBuild projects' });
            codebuildValidSourceProviders.run(cache, { codebuild_disallowed_source_providers: 's3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to query CodeBuild project', function (done) {
            const cache = createCache(listProjects, null, null, { message: 'Unable to query CodeBuild project' });
            codebuildValidSourceProviders.run(cache, { codebuild_disallowed_source_providers: 's3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});

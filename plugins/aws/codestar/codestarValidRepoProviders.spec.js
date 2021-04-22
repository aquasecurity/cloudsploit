var expect = require('chai').expect;
const codestarValidRepoProviders = require('./codestarValidRepoProviders');

const listProjects = [
    {
        "projectId": "aqua-project",
        "projectArn": "arn:aws:codestar:us-east-1:111222333444:project/aqua-project"
    }
];


const describeProject = {
    "name": "aqua-project",
    "id": "aqua-project",
    "arn": "arn:aws:codestar:us-east-1:000111222333:project/aqua-project",
    "description": "AWS CodeStar created project",
    "createdTimeStamp": 1617967855.647,
    "projectTemplateId": "arn:aws:codestar:us-east-1::project-template/github/webapp-nodeweb-lambda",
};

const createCache = (listProjects, describeProject, listProjectsErr, describeProjectErr) => {
    let project = (listProjects && listProjects.length) ? listProjects[0].projectId : null;
    return {
        codestar: {
            listProjects: {
                'us-east-1': {
                    data: listProjects,
                    err: listProjectsErr
                }
            },
            describeProject: {
                'us-east-1': {
                    [project]: {
                        data: describeProject,
                        err: describeProjectErr
                    }
                }
            }
        }
    }
};

const createNullCache = () => {
    return {
        codestar: {
            listProjects: {
                'us-east-1': null,
            },
        },
    };
};

describe('codestarValidRepoProviders', function () {
    describe('run', function () {
        it('should PASS if CodeStar project is using allowed repo providers', function (done) {
            const cache = createCache(listProjects, describeProject);
            codestarValidRepoProviders.run(cache, { codestar_disallowed_repo_providers: 'codecommit'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CodeStar project is not using allowed source providers', function (done) {
            const cache = createCache(listProjects, describeProject);
            codestarValidRepoProviders.run(cache, { codestar_disallowed_repo_providers: 'github' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no CodeStar projects found', function (done) {
            const cache = createCache([]);
            codestarValidRepoProviders.run(cache, { codestar_disallowed_repo_providers: 's3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query CodeStar projects', function (done) {
            const cache = createCache(listProjects, { message: 'Unable to query CodeStar projects' });
            codestarValidRepoProviders.run(cache, { codestar_disallowed_repo_providers: 's3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query CodeStar project', function (done) {
            const cache = createCache(listProjects, null, null, { message: 'Unable to query CodeStar project' });
            codestarValidRepoProviders.run(cache, { codestar_disallowed_repo_providers: 's3' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
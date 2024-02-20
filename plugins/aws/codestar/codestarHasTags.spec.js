var expect = require('chai').expect;
const codestarHasTags = require('./codestarHasTags');

const listProjects = [
    {
        "projectId": "aqua-project",
        "projectArn": "arn:aws:codestar:us-east-1:111222333444:project/aqua-project"
    }
];

const getResources = [
    {
        "ResourceARN": "arn:aws:codestar:us-east-1:111222333444:project/aqua-project",
        "Tags": [],
    },
     {
        "ResourceARN": "arn:aws:codestar:us-east-1:111222333444:project/aqua-project",
        "Tags": [{key: 'value'}],
    }
]


const createCache = (listProjects, rgData) => {
    return {
        codestar: {
            listProjects: {
                'us-east-1': {
                    err: null,
                    data: listProjects
                }
            },
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
    };
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


describe('codestarHasTags', function () {
    describe('run', function () {
        it('should PASS if CodeStar project has tags', function (done) {
            const cache = createCache([listProjects[0]], [getResources[1]]);
            codestarHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CodeStar project doesnot have tags', function (done) {
            const cache = createCache([listProjects[0]], [getResources[0]]);
            codestarHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no CodeStar projects found', function (done) {
            const cache = createCache([]);
            codestarHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query CodeStar project', function (done) {
            const cache = createCache(listProjects, null, null, { message: 'Unable to query CodeStar project' });
            codestarHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([listProjects[0]],null);
            codestarHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
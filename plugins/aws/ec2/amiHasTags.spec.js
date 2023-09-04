var expect = require('chai').expect;
const amiHasTags = require('./amiHasTags');

var describeImages = [
   { 
    Tags: [{ Key: 'key', value: 'value' }],
    ImageId: 'ami-046b09f5340dfd8gb'

   },
    { 
    Tags: [],
    ImageId: 'ami-046b09f5340dfd8gb'

   }
]

const createCache = (instances) => {
    return {
        ec2: {
            describeImages: {
                'us-east-1': {
                    data: instances
                },
            },
        },
    };
};


describe('amiHasTags', function () {
    describe('run', function () {
      
        it('should return UNKNOWN result if error occurs while describing AMIs', function (done) {
            const cache = createCache(null);
            amiHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for AMIs');
                done();
            });
        });

        it('should return Passing result if no AMI found', function (done) {
            const cache = createCache([]);
            amiHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No AMIs found');
                done();
            });
        });

        it('should return Passing result if AMI tags', function (done) {
            const cache = createCache([describeImages[0]]);
            amiHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('AMI has tags');
                done();
            });
        });

        it('should return Fail result if EC2 instance has no tags', function (done) {
            const cache = createCache([describeImages[1]]);
            amiHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('AMI does not have any tags');
                done();
            });
        });

    });
});
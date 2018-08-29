var async = require('async');
var helpers = require('../../helpers');

module.exports = {
  title: 'Notebook Data Encrypted',
  category: 'SageMaker',
  description: 'Ensure Notebook data is encrypted',
  more_info: 'An optional Encryption key can be supplied durning Notebook Instance creation.',
  recommended_action: 'An existing KMS key should be supplied durning Notebook Instance creation.',
  link: 'https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateNotebookInstance.html#API_CreateNotebookInstance_RequestSyntax',
  apis: ['SageMaker:listNotebookInstances', 'SageMaker:describeNotebookInstance'],

  run: function(cache, settings, callback) {
    var results = [];
    var source = {};

    async.each(helpers.regions.sagemaker, function(region, rcb){
      var listNotebookInstances = helpers.addSource(cache, source,
        ['sagemaker', 'listNotebookInstances', region]);

      if (!listNotebookInstances) return rcb();

      if (listNotebookInstances.err) {
        helpers.addResult(results, 3,
          'Unable to query for Notebook Instances: '
          + helpers.addError(listNotebookInstances), region);
        return rcb();
      }

      if (!listNotebookInstances.data || !listNotebookInstances.data.length) {
        helpers.addResult(
          results, 0, 'No Notebook Instances Found', region);
        return rcb();
      }

      var describeNotebookInstances = helpers.addSource(cache, source,
      ['sagemaker', 'describeNotebookInstance', region]);

      for( i in describeNotebookInstances){
        var instance = describeNotebookInstances[i].data;
        var instanceArn = instance.NotebookInstanceArn;

        if (!instance.KmsKeyId){
          helpers.addResult(results, 2,
            'KmsKeyId not found for Notebook Instance', region, instanceArn);
        }
      }

      rcb();
    }, function(){
      callback(null, results, source);
    });
  }
};

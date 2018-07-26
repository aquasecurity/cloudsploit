var async = require('async');
var helpers = require('../../helpers');

module.exports = {
  title: 'Notebook Direct Internet Access',
  category: 'SageMaker',
  description: 'Ensure Notebook Instance is not publicly available.',
  more_info: 'Public availability can be configured via the DirectInternetAccess attribute.',
  recommended_action: 'DirectInternetAccess should be Disabled.',
  link: 'https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-additional-considerations.html#appendix-notebook-and-internet-access',
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

        if (instance.DirectInternetAccess == 'Enabled'){
          helpers.addResult(results, 2,
            'Direct Internet Access Enabled', region, instanceArn);
        }
      }

      rcb();
    }, function(){
      callback(null, results, source);
    });
  }
};

Event.observe(window, 'load', function() {

	var sparkBar = new Grafico.SparkBar($('mailHistory'), [30, 15, 50, 20, 50, 12, 45]);
	var sparkBar = new Grafico.SparkLine($('responseTime'), [341,50,123,54,14,69,5]);

	Event.observe("login_button", "click", function() {
		$$('.login')[0].addClassName('inbox')
		$$('.login')[0].removeClassName('login')
		return false;
	});

});

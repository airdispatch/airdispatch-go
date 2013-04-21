Event.observe(window, 'load', function() {

	/*
	var streamGraph = new Grafico.StackGraph($('mailHistory'),
		{
			normalMail: [20, 40, 10, 5, 4, 30, 40],
			newsletters: [5, 10, 15, 20, 6, 6, 2]
		},
		{
			background_color: '#e0e0e0',
			draw_axis: false,
			grid: false,
			draw_hovers: true,
			datalabels: {
				normalMail: "Normal Email",
				newsletters: "Newsletters"
			},
		}
	);
	*/

	var sparkBar = new Grafico.SparkBar($('mailHistory'), [30, 15, 50, 20, 50, 12, 45]);
	var sparkBar = new Grafico.SparkLine($('responseTime'), [30, 15, 50, 20, 50, 12, 45]);

});

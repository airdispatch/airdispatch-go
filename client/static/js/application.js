Event.observe(window, 'load', function() {

	var streamGraph = new Grafico.StreamGraph($('mailHistory'),
		{
			normalMail: [20, 40, 10, 5, 4],
			newsletters: [5, 10, 15, 20]
		},
		{
			background_color: '#e0e0e0',
			draw_hovers: true,
			stream_label_threshold: 20,
			labels: true,
			stream_line_smooting: 'simple',
			datalabels: {
				normalMail: "Normal Email",
				newsletters: "Newsletters"
			},
		}
	);

});

/*
 Template Name: Zoogler - Bootstrap 4 Admin Dashboard
 Author: Mannatthemes
 Website: www.mannatthemes.com
 File: Vector Maps
 */

!function($) {
    "use strict";

    var VectorMap = function() {};


    VectorMap.prototype.init = function() {
		
		$('#world-map-markers').vectorMap({
			map: 'world_mill_en',
			scaleColors: ['#f75d8c', '#f75d8c'],
			normalizeFunction: 'polynomial',
			hoverOpacity: 0.7,
			hoverColor: false,
			regionStyle: {
				initial: {
					fill: '#605daf'
				}
			},
			markerStyle: {
				initial: {
					r: 9,
					'fill': '#f75d8c',
					'fill-opacity': 0.9,
					'stroke': '#fff',
					'stroke-width': 7,
					'stroke-opacity': 0.4
				},
				hover: {
					'stroke': '#fff',
					'fill-opacity': 1,
					'stroke-width': 1.5
				}
			},
			backgroundColor: 'transparent',
			markers: [
				{
				latLng: [38.83, -77.04],
				name: 'us-east-1'
			},
			{
				latLng: [39.05, -84.51],
				name: 'us-east-2'
			},
			{
				latLng: [37.77, -122.42],
				name: 'us-west-1'
			},
			{
				latLng: [45.52, -122.68],
				name: 'us-west-2'
			},
			{
				latLng: [45.42, -75.70],
				name: 'ca-central-1'
			},
			{
				latLng: [53.35, -6.26],
				name: 'eu-west-1'
			},
			{
				latLng: [51.51, -0.12],
				name: 'eu-west-2'
			},
			{
				latLng: [50.11, 8.68],
				name: 'eu-central-1'
			},
			{
				latLng: [19.08, 72.88],
				name: 'ap-south-1</br>Hello',

			},
			{
				latLng: [1.35, 103.82],
				name: 'ap-southeast-1'
			}]
		});

        
  },
    //init
    $.VectorMap = new VectorMap, $.VectorMap.Constructor = VectorMap
}(window.jQuery),

//initializing 
function($) {
    "use strict";
    $.VectorMap.init()
}(window.jQuery);

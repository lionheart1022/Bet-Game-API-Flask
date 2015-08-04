var API = {
	call: function(method, endpoint, data, success, failure) {
		return $.ajax({
			dataType: 'json',
			method: method,
			url: '/v1/'+endpoint,
			data: data,
			complete: function(xhr, stat) {
				var data = xhr.responseJSON;
				if(xhr.status >= 200 && xhr.status < 300) {
					if(success)
						success(data);
				} else {
					console.error('API error', stat, data);
					if(failure)
						failure(data, xhr.status);
				}
			},
		});
	},
};


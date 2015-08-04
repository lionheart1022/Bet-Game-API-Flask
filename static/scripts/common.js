var API = {
	token: null,
	call: function(method, endpoint, data, success, failure) {
		var headers = {};
		if(this.token)
			headers['Authorization'] = 'Bearer '+this.token;
		return $.ajax({
			dataType: 'json',
			method: method,
			url: '/v1/'+endpoint,
			headers: headers,
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


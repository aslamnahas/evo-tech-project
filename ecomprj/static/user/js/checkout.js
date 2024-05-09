document.addEventListener('DOMContentLoaded', function() {
    var payButton = document.querySelector('.paywithrazorpay');
    console.log("This page is loaded")

    payButton.addEventListener('click', function(event) {
        event.preventDefault();

        var selects = document.querySelector("[name='addressId']").value;

        if (selects === "") {
            swal("Alert", "Address field is needed", "error");
            return false;
        } else {
            console.log("Razorapay is loaded")
            fetch('/proceed-to-pay')
                .then(function(response) {
                    return response.json();
                })
                .then(function(data) {
                    var options = {
                        key: 'rzp_test_oR7x1WyMRe9zxr',
                        amount: data.total * 100,
                        currency: 'INR',
                        name: 'techzone',
                        description: 'Thank you for Placing an order ',
                        image: 'https://static-00.iconduck.com/assets.00/bill-payment-icon-2048x2048-vpew78n5.png',
                        handler: function(responseb) {
                            window.location.href = '/razorpay/' + selects;
                        },
                        prefill: {
                            name: '',
                            email: '',
                            contact: ''
                        },
                        notes: {
                            address: 'Razorpay Corporate Office'
                        },
                        theme: {
                            color: '#D19C97'
                        }
                    };

                    var rzp1 = new Razorpay(options);
                    rzp1.open();
                })
                .catch(function(error) {
                    console.error('Error:', error);
                });
    }
   });
});
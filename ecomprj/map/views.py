# from django.shortcuts import render
# from geopy.geocoders import Nominatim
# from geopy import distance
# def new(request):
#     geocoder = Nominatim(user_agent="nahjas")  # Use user_agent instead of user

#     location1 = "Manjeshwaram"
#     location2 = "Manglore"

#     cor1 = geocoder.geocode(location1)
#     cor2 = geocoder.geocode(location2)
   

#     lat1,long1 = (cor1.latitude),(cor1.longitude)
#     lat2,long2 = (cor2.latitude),(cor2.longitude)
#     place1 = (lat1,long1)
#     place2 = (lat2,long2)

#     print(distance.distance(place1,place2))
    
#     # print(cor1.longitude)
#     # print(cor2.longitude)
#     return render(request, 'core/new.html')

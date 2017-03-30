# mezcalbeneva
maqueteo pagina web beneva
- [ ] I have written a descriptive pull-request title
  - [ ] I have verified that there are no overlapping [pull-requests] open
(https://github.com/NancyFx/Nancy/blob/45238076ad0b7f6ecabd6bae8469e30458d02efe/CONTRIBUTING.md#style-guidelines)
 -- [ ] I have provided test coverage for your change (where applicable)
 (https://github.com/NancyFx/Nancy/blob/45238076ad0b7f6ecabd6bae8469e30458d02efe/CONTRIBUTING.md#style-guidelines)
 +- [ ] I have provided test coverage for my change (where applicable)
 @@ -1,8 +1,10 @@
  #! /bin/bash
  
 -# Run firebase db backup at 2am weekly
 +# Run firebase db backup at 2am Sunday every week
 +day=$(date '+%a')
  hour=$(date '+%H')
 -if [ $hour == 02 ]; then
 +
 +if [ $hour == 02 ] && [ $day == 'Sun' ]; then
  	curl -X POST --data "secret=$WEBUILD_API_SECRET" $WEBUILD_URL/api/v1/backups/update
  	curl -X DELETE --data "secret=$WEBUILD_API_SECRET" $WEBUILD_URL/api/v1/events/cleanup
    @@ -1,6 +1,6 @@
  #! /bin/bash
  
 -# Run archival at 3am
 +# Run archival at 3am every day
  hour=$(date '+%H')
  if [ $hour == 03 ]; then
  	curl -X POST --data "secret=$WEBUILD_API_SECRET" $WEBUILD_URL/api/v1/archives/update
  

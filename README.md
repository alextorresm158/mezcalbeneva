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
    var fs = require('fs');
 +
 +var crypto = require('crypto')
 +var algorithm = 'aes-256-gcm'
 +var password = process.env.FIREBASE_PASSWORD
 +var iv = process.env.FIREBASE_IV
 +
 +function encrypt(text) {
 +  var cipher = crypto.createCipheriv(algorithm, password, iv)
 +  var encrypted = cipher.update(text, 'utf8', 'hex')
 +  encrypted += cipher.final('hex');
 +  var tag = cipher.getAuthTag();
 +  return {
 +    content: encrypted,
 +    tag: tag
 +  };
 +}
 +
 +fs.readFile('private.json', 'utf8', function(err, data) {
 +    if (err) throw err;
 +    fs.writeFile('private.enc.json', JSON.stringify(encrypt(data)), 'utf8', function(err) {
 +        if (err) throw err;
 +    });
 +});
 +{"content":"b6c8b30bd19d4db27abee587877bbcf7969f687ebdf5172a15fb10b6ae9379759975b809aecc145ed95e79e0867e446d27749c7d885dd1ac06201cb2f0e9c728229869d7575599f92449f678a2b45e31cfdb772ea3c09acb4ccce4c15b72f80e5765d6e72d4e6ea098f48309fefb1cbf114a49963590aaeee4c51d4d5c2698b33c649e875a0cb66427694dc41f2e2de81430f1d7f23d8bc568a07bbd38e15776fa2c58cf416bb034fc8d198e70c5770e869ab9db91f58186130e89eb67ae70a6a28370a6cadc93a3aece8cb7c1ae778fbb7931854556166a8c4d455c93d09dd098de97d6f27a252f9eb304b57d8933598dc49a829cb9dd395e8822b37bbb21a70af2f690c40da7161f3f66a39751102c09951117c4b92d018027b82977a7e8c941eb1f9ea4b49ba0aa3cf3e2461b38927b1c0d559fee7b0fe3cec98cf587b76a88f14119ffde232b84cd7169ff1a35b1f060bc17b6a4a6034b3134ab0426d97e4f7d50362ec5daefe02d15a483cecd8f95d453c40d11d54a4e57546bc10ea3f2cf165d58034260b93f50b092c3ef52cbafc92157413d9f958e5601f58cce52dfd81db84de1410cdc76e5d90df8c8951f81ccba0c745dc47802122ac30955c6008a24397a43a03601b8946b685fedabb25377e37359f13d3f7953cdc75a4bcb5dde063bce6c3d92e426fe7c3c15f56483bb806266a11343ba010674a5cd60eff4ea14509c64013bde3dd790f947341554ed85137a2bba929377085942e6f2ca769f70c33bb68dac04cd871c8708cfed7d0724810cc6eec026e47c254e07d91436aa4966022d8ecc4ae994ff06e5d3f0194936ae9cab4361a3a2425c503526c124663d859b4ffab96602a693fa25c7b3026f413598f0d912836a14914ed9a01e02d2759d781cb13778eea50e96b5a725647280cf4ac24a7a2e4f7f267ee1a0295777d09cf64c6c9da778205d9378ba6d35bd5d3754a97920f227351cd665239f1b6115ed1d1bdc4bcc94bc3d2725730fb9bd7f3a70ffa78bf2eb23d6ea267b3cd75d724b87017d3b5f31bf939fb5790791900b09a8eb4315b06f57d9902e70b72323d4848148560cbb77696b652acd28ce3874068e706f0249e16a3cbb484e70166452c1d2894f817e60e473c3380eb419bf5619e3875bba31b76d30f5de1140205d6258ff17b513a318009cb22019d6178a1745b3eb8e75e64ec051e3699082e475725f3e161caa25adf215034bc62ed1b25d129118d4fe55b8cc395dbeb222a59c6c07e4ebc706cb26399e58887b2c982190bdd0546f399c0c3a913c9d73e0695102d1cf8b80c59e7c1092421a916f42d0c0349a7e039670e3ccdf8614206d4e958b4bc17e7e32128062aa4850629822fd4b048580bbd687808d7f1af5e20ced43a57a299bc74f2632746fd6de4e5f55433374a39193275645adaf88c3b759cbfcfe2999c45aa00f0a78de245566b8581e1330b325fa00512157c1319b3a82499338924245a60471ba1d20d4db261ea16d8710356744602a7fd65e91b7c813d1e8fd2e2d1a97e38b064641c5c4f66e1037c27d1253d127f640b36cf67cf3239c09910ca3d7a8ac657f56cff72635301f56d270033deffde87698613a5a080f05b95273748cfc2a620a114ebddb7b8c5c2acd0bc55cc49f1dd0b0649c089ac64b559b540e319b125da4bfb0138a248a87cccff36271caa484fcf93dc36772b4f8bebebc65ecf87ef3a92dba8629adeda0aafb034de64780e846253bc72d352fa6f833fb39a89564188bb22ac1f4a64d0d1fd348c80eb51d3a587a39cc7c40b9fd5a5971584bceee3c18d7adadbe44dbca054cc731f8366dc03ba29b50db6ab95c47ce723c689f4e63162007a150f115335e0cc3f101fb58212eeb256c9816ca12c7e70df03e95a4ce6a7a6f4dd0538269713f5905cd3851fbd4a6b09c5a14b4a1a089b21a04a91b9b8cc84916e1f9635118a28f3bc24b66d2823e79a376d9d49391a33ae8a9c3a086e9360a77ea2a8aa9017832d5c4c36a106c28e3120b2150820b49d2a661648389818300fad0bf8f55e66a519bd74b2bdbfcbfb82d5d4f08d781188c7aa70d446e7ae48e45038c871195d70f805fb74eaf253dbd280b756bc969495a8f185c943e7fd5cdd6bc24e3d006882fbc0a3de19e078044ed1774f98642c74c4924f72bc0a32200a08a3fe278beccf786a83ab200c16c22c06c1e80afe4a65d1c93bf2e96b148c5547f911e745fec8aab27b0e1087ae2dc2ae2777448abe33ec917a6de7d401d170293de511d41cb279f4e9e68c4534230b3277da0282d86f01bd78616b9d2e2f431e049171606a71bd4bdb35e180f93fb7ab05486bc79af3b24c214a4c237e34c26869cec13149e2ed55bb32d74069e5083ff3f347b0ddf7969784c2ffa03493e1eec22c53a5bc4feac1bc48fcca05d966bd600f7da3cfda63c9c1409117372b15c3191b52aec383324f752837106110bec2e502dbb7afec0f5e903b142003381906a02976308bb499dd94db5c88590d25c2b1662ca6aff1647dcba6109ad11e00befad05d5b2f06120e331679a25c35dd862d97b5e14715680728366ecb425eb0f0d142e5327015ad93eb647eac0acb516e1e2cb9fba5a036966c4d5754b1c5de2e69b4c584e3f5cf59c437ae30509b7565bec5783db41dcd7968be446b7832357fd46eff9146daacdc0b9fde77e2efffbc306add78718a3e2e1adbfd17f068800066b3ebadf1ff27b144943f8ebc21b66376d9042d88cd442c8c034d0b3d54a9245d644a315141f782eba0dbdf22a705fa178d54c35d9be22be8e6b8068c3ba50dfa34ea9f1e04fb7c11379e318e4dbf1c4137792789a905c0c8ec53bf7824ed1b901bfa4ac34ef07f1318ef6b81f6e92be365b026b2cf2038e863ebe9e64049f02145d7731efe215b8953d8844cf09feacbc4372d64047c8fdf42212bf8d0aec4ca5235040ba51545bac67b888d4ba7dba9571dddc8b0e9ab5a108fd162ac3245a492d78cc4a1d17eda36f8685758424477bed3d983125f14c0865a16f3a045fc05270f53d065705c5ae2fb5abf208e9cddf94100e3b6c95666777204e7862458a1b1cc7d52ea3c7cd652f42b05d85a772bad3ce696c0f9199834c30b8f3c169020cedf7fa85d158d0b700870fbd7879fb70469e4bdff7bfa43df09ec0babe919514e08faf5c835febd9ce39c2ebad452ce9e23abd49dcd2835b448122834bcc18ac400c3f1d8fa36fc40d1d91404146846c82f07830f75631964c2c07ade3f7b94321c5ebc1aac081d4942d14a4af7c4b7344727f045c87dbccbe686923b9d15894330cc7cfc97d8820e74b7a15f639f4de9613f20bbbaab92f9ba80836abca0ffb53d87cd4fa236cc217","tag":{"type":"Buffer","data":[114,74,148,58,170,116,129,164,115,60,226,85,161,28,168,147]}}
 var firebase = require('firebase')
  var logger = require('./logger')
 +var crypto = require('crypto')
  
 -// Initialize the app with a service account, granting admin privileges
 -
 -var serviceAccountCredentials = {
 -  "type": "service_account",
 -  "project_id": process.env.FIREBASE_PROJECT_ID,
 -  "private_key_id": process.env.FIREBASE_PRIVATE_KEY_ID,
 -  "private_key": process.env.FIREBASE_PRIVATE_KEY,
 -  "client_email": "firebase-service-account@" + process.env.FIREBASE_PROJECT_ID + ".iam.gserviceaccount.com",
 -  "client_id": process.env.FIREBASE_CLIENT_ID,
 -  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
 -  "token_uri": "https://accounts.google.com/o/oauth2/token",
 -  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
 -  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-service-account%40" + process.env.FIREBASE_PROJECT_ID + ".iam.gserviceaccount.com"
 +
 +function decrypt(encrypted) {
 +  var decipher = crypto.createDecipheriv(algorithm, password, iv)
 +  decipher.setAuthTag(encrypted.tag);
 +  var dec = decipher.update(encrypted.content, 'hex', 'utf8')
 +  dec += decipher.final('utf8');
 +  return dec;
  }
  
 +
 +var algorithm = 'aes-256-gcm'
 +var password = process.env.FIREBASE_PASSWORD
 +var iv = process.env.FIREBASE_IV
 +
 +// This is what we will do in the app
 +var encryptedPrivateKey = require('../private.enc.json');
 +encryptedPrivateKey.tag = new Buffer(encryptedPrivateKey.tag.data);
 +
 +var decryptedPrivateKey = JSON.parse(decrypt(encryptedPrivateKey));
 +
  firebase.initializeApp({
      databaseURL: process.env.FIREBASE_URL,
 -    serviceAccount: serviceAccountCredentials
 +    serviceAccount: decryptedPrivateKey
  });
   footer
    .container
 -    <p>Checkout more cool events and people in startup, arts and tech with <br><a href="http://thelist.sg/">thelist.sg</a>, <a href="http://connections.sg/">connections.sg</a>, <a href="http://hackerspace.sg/calendar/hackerspacesg-events/">hackerspace</a>, <a href="http://bhappening.wordpress.com/">bhappening</a>, <a href="http://www.techinasia.com/tech-startup-events/">tech in asia</a></p>
 +    <p>Checkout <a href="/about">what is We Build SG</a> and <a href="/faq">how the events and repositories are curated</a>!</p>
  
  ul.social
    li
    node_modules/*
  
  public/js/vendor/*
 -!public/js/vendor/auth0-widget.js
 -public/js/vendor/auth0-widget.js/*
 -!public/js/vendor/auth0-widget.js/build
 -public/js/vendor/auth0-widget.js/build/auth0-widget.js
 -
  public/css/style.css
  cache.json
  events.json
"dependencies": {
      "fluidvids": "2.4.1",
 -    "moment": "2.13.0",
 -    "auth0-widget.js": "5.2.13"
 +    "moment": "2.13.0"
 -  script(src='public/js/vendor/auth0-widget.js/build/auth0-widget.min.js')
 +  script(src='public/js/auth0-widget.min.js')
    script(type='text/javascript').
      var widget = new Auth0Widget({domain: '#{auth0.domain}', clientID: '#{auth0.clientId}', callbackURL: window.location.origin + '/callback'});
      widget.signin({container: 'auth0', connections: ['facebook'], chrome: true, scope: 'openid profile user_groups user_events'},function(){
+# www.robotstxt.org/
 +
 +# Allow crawling of all content
 +User-agent: *
 +Disallow:
   .range([0, width])
    var y = d3.scaleLinear()
      .range([height, 0])
 +    .tickFormat(5, "+%");
    var svg = d3.select('.chart').append('svg')
      .attr('width', width + margin.left + margin.right)
      .attr('height', height + margin.top + margin.bottom)
      svg.append('g')
        .attr('class', 'y axis')
 -      .call(d3.axisLeft(y).ticks(maxY, "d"))
 +      .call(d3.axisLeft(y))
        .append('text')
        .attr('transform', 'rotate(-90)')
        .attr('y', 6)
        !SESSION 2007-07-03 12:00:48.815 -----------------------------------------------
 -eclipse.buildId=M20060921-0945
 -java.version=1.5.0_07
 -java.vendor=Apple Computer, Inc.
 -BootLoader constants: OS=macosx, ARCH=x86, WS=carbon, NL=en_US
 -Framework arguments:  -keyring /Users/nicolawilkinson/.eclipse_keyring -showlocation
 -Command-line arguments:  -os macosx -ws carbon -keyring /Users/nicolawilkinson/.eclipse_keyring -consoleLog -showlocation
 -
 -!ENTRY org.eclipse.osgi 4 0 2007-07-03 12:01:42.424
 -!MESSAGE While loading class "net.sourceforge.phpeclipse.PHPeclipsePlugin$3$1", thread "Worker-2" timed out waiting (5000ms) for thread "main" to finish starting bundle "net.sourceforge.phpeclipse". To avoid deadlock, thread "Worker-2" is proceeding but "net.sourceforge.phpeclipse.PHPeclipsePlugin$3$1" may not be fully initialized.
 -!STACK 0
 -java.lang.Exception: Generated exception.
 -	at org.eclipse.core.runtime.internal.adaptor.EclipseLazyStarter.preFindLocalClass(EclipseLazyStarter.java:75)
 -	at org.eclipse.osgi.baseadaptor.loader.ClasspathManager.findLocalClass(ClasspathManager.java:409)
 -	at org.eclipse.osgi.internal.baseadaptor.DefaultClassLoader.findLocalClass(DefaultClassLoader.java:188)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findLocalClass(BundleLoader.java:334)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findClass(BundleLoader.java:386)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findClass(BundleLoader.java:347)
 -	at org.eclipse.osgi.internal.baseadaptor.DefaultClassLoader.loadClass(DefaultClassLoader.java:83)
 -	at java.lang.ClassLoader.loadClass(ClassLoader.java:251)
 -	at java.lang.ClassLoader.loadClassInternal(ClassLoader.java:319)
 -	at net.sourceforge.phpeclipse.PHPeclipsePlugin$3.run(PHPeclipsePlugin.java:1182)
 -	at org.eclipse.core.internal.jobs.Worker.run(Worker.java:58)
 org.eclipse.jface.textfont=1|Monaco|11|0|CARBON|1|;
 -eclipse.preferences.version=1
 -fontPropagated=true
 -useQuickDiffPrefPage=true
 -tabWidthPropagated=true
 -proposalOrderMigrated=true
 -org.eclipse.jdt.ui.javadoclocations.migrated=true
 -useAnnotationsPrefPage=true
 -org.eclipse.jface.textfont=1|Monaco|11|0|CARBON|1|;
 -org.eclipse.jdt.ui.editor.tab.width=
 -org.eclipse.jdt.ui.formatterprofiles.version=10
 -eclipse.preferences.version=1
 -fontPropagated=true
 <?xml version="1.0" encoding="UTF-8"?>
 -<section name="Workbench">
 -	<section name="org.eclipse.jdt.ui.internal.packageExplorer">
 -		<item key="memento" value="&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&#x0A;&lt;packageexplorer isWindowWorkingSet=&quot;true&quot; layout=&quot;2&quot; org.eclipse.jdt.ui.packages.linktoeditor=&quot;0&quot; rootMode=&quot;1&quot; workingSetName=&quot;&quot;&gt;&#x0A;&lt;customFilters userDefinedPatternsEnabled=&quot;false&quot;&gt;&#x0A;&lt;xmlDefinedFilters&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.FieldsFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer_patternFilterId_.*&quot; isEnabled=&quot;true&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.LocalTypesFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer_patternFilterId_*$*.class&quot; isEnabled=&quot;true&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.NonPublicFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.internal.ui.PackageExplorer.EmptyPackageFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.LibraryFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.NonJavaProjectsFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.ContainedLibraryFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.ImportDeclarationFilter&quot; isEnabled=&quot;true&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.StaticsFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.NonSharedProjectsFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.internal.ui.PackageExplorer.EmptyInnerPackageFilter&quot; isEnabled=&quot;true&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.SyntheticMembersFilter&quot; isEnabled=&quot;true&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.NonJavaElementFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.ClosedProjectsFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.CuAndClassFileFilter&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.pde.ui.BinaryProjectFilter1&quot; isEnabled=&quot;false&quot;/&gt;&#x0A;&lt;child filterId=&quot;org.eclipse.jdt.ui.PackageExplorer.PackageDeclarationFilter&quot; isEnabled=&quot;true&quot;/&gt;&#x0A;&lt;/xmlDefinedFilters&gt;&#x0A;&lt;/customFilters&gt;&#x0A;&lt;/packageexplorer&gt;"/>
 -	</section>
 -</section>
 -<?xml version="1.0" encoding="UTF-8"?>
 -<workbench progressCount="15" version="2.0">
 -<workbenchAdvisor/>
 -<window height="768" width="1024" x="10" y="54">
 -<fastViewData fastViewLocation="1024"/>
 -<intro standby="false"/>
 -<perspectiveBar>
 -<itemSize x="160"/>
 -</perspectiveBar>
 -<coolbarLayout locked="0">
 -<coolItem id="group.file" itemType="typeGroupMarker"/>
 -<coolItem id="org.eclipse.ui.workbench.file" itemType="typeToolBarContribution" x="0" y="22"/>
 -<coolItem id="additions" itemType="typeGroupMarker"/>
 -<coolItem id="org.eclipse.debug.ui.launchActionSet" itemType="typeToolBarContribution" x="0" y="22"/>
 -<coolItem id="org.eclipse.jdt.ui.JavaElementCreationActionSet" itemType="typeToolBarContribution" x="0" y="22"/>
 -<coolItem id="org.eclipse.search.searchActionSet" itemType="typeToolBarContribution" x="0" y="22"/>
 -<coolItem id="org.eclipse.ui.WorkingSetActionSet" itemType="typeToolBarContribution" x="0" y="22"/>
 -<coolItem id="group.nav" itemType="typeGroupMarker"/>
 -<coolItem id="org.eclipse.ui.workbench.navigate" itemType="typeToolBarContribution" x="156" y="22"/>
 -<coolItem id="group.editor" itemType="typeGroupMarker"/>
 -<coolItem id="group.help" itemType="typeGroupMarker"/>
 -<coolItem id="org.eclipse.ui.workbench.help" itemType="typeToolBarContribution" x="-1" y="-1"/>
 -</coolbarLayout>
 -<page aggregateWorkingSetId="Aggregate for window 1183460477279" focus="true" label="Workspace - Java">
 -<editors>
 -<editorArea activeWorkbook="DefaultEditorWorkbook">
 -<info part="DefaultEditorWorkbook">
 -<folder appearance="1" expanded="2">
 -<presentation id="org.eclipse.ui.presentations.WorkbenchPresentationFactory"/>
 -</folder>
 -</info>
 -</editorArea>
 -</editors>
 -<views>
 -<view id="org.eclipse.jdt.ui.JavadocView" partName="Javadoc"/>
 -<view id="org.eclipse.ui.views.ContentOutline" partName="Outline">
 -<viewState/>
 -</view>
 -<view id="org.eclipse.ui.internal.introview" partName="Welcome">
 -<viewState>
 -<presentation currentPage="root" restore="true"/>
 -<standbyPart/>
 -</viewState>
 -</view>
 -<view id="org.eclipse.jdt.ui.SourceView" partName="Declaration"/>
 -<view id="org.eclipse.jdt.ui.PackageExplorer" partName="Package Explorer">
 -<viewState isWindowWorkingSet="true" layout="2" org.eclipse.jdt.ui.packages.linktoeditor="0" rootMode="1" workingSetName="">
 -<customFilters userDefinedPatternsEnabled="false">
 -<xmlDefinedFilters>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.FieldsFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer_patternFilterId_.*" isEnabled="true"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.LocalTypesFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer_patternFilterId_*$*.class" isEnabled="true"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.NonPublicFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.internal.ui.PackageExplorer.EmptyPackageFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.LibraryFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.NonJavaProjectsFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.ContainedLibraryFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.ImportDeclarationFilter" isEnabled="true"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.StaticsFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.NonSharedProjectsFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.internal.ui.PackageExplorer.EmptyInnerPackageFilter" isEnabled="true"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.SyntheticMembersFilter" isEnabled="true"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.NonJavaElementFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.ClosedProjectsFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.CuAndClassFileFilter" isEnabled="false"/>
 -<child filterId="org.eclipse.pde.ui.BinaryProjectFilter1" isEnabled="false"/>
 -<child filterId="org.eclipse.jdt.ui.PackageExplorer.PackageDeclarationFilter" isEnabled="true"/>
 -</xmlDefinedFilters>
 -</customFilters>
 -</viewState>
 -</view>
 -<view id="org.eclipse.jdt.ui.TypeHierarchy" partName="Hierarchy"/>
 -<view id="org.eclipse.ui.views.ProblemView" partName="Problems">
 -<viewState columnWidth0="274" columnWidth1="99" columnWidth2="174" columnWidth3="84" columnWidth4="0" horizontalPosition="0" verticalPosition="0">
 -<columnOrder columnOrderIndex="0"/>
 -<columnOrder columnOrderIndex="1"/>
 -<columnOrder columnOrderIndex="2"/>
 -<columnOrder columnOrderIndex="3"/>
 -<columnOrder columnOrderIndex="4"/>
 -</viewState>
 -</view>
 -</views>
 -<perspectives activePart="org.eclipse.ui.internal.introview" activePerspective="org.eclipse.jdt.ui.JavaPerspective">
 -<perspective editorAreaVisible="1" fixed="0" version="0.016">
 -<descriptor class="org.eclipse.jdt.internal.ui.JavaPerspectiveFactory" id="org.eclipse.jdt.ui.JavaPerspective" label="Java"/>
 -<alwaysOnActionSet id="org.eclipse.ui.cheatsheets.actionSet"/>
 -<alwaysOnActionSet id="org.eclipse.search.searchActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.ui.edit.text.actionSet.openExternalFile"/>
 -<alwaysOnActionSet id="org.eclipse.ui.edit.text.actionSet.annotationNavigation"/>
 -<alwaysOnActionSet id="org.eclipse.ui.edit.text.actionSet.navigation"/>
 -<alwaysOnActionSet id="org.eclipse.ui.edit.text.actionSet.convertLineDelimitersTo"/>
 -<alwaysOnActionSet id="org.eclipse.ui.externaltools.ExternalToolsSet"/>
 -<alwaysOnActionSet id="org.eclipse.ui.actionSet.keyBindings"/>
 -<alwaysOnActionSet id="org.eclipse.ui.WorkingSetActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.update.ui.softwareUpdates"/>
 -<alwaysOnActionSet id="org.eclipse.debug.ui.launchActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.jdt.ui.JavaActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.jdt.ui.JavaElementCreationActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.ui.NavigateActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.debug.ui.breakpointActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.jdt.debug.ui.JDTDebugActionSet"/>
 -<alwaysOnActionSet id="org.eclipse.jdt.junit.JUnitActionSet"/>
 -<show_view_action id="org.eclipse.jdt.ui.PackageExplorer"/>
 -<show_view_action id="org.eclipse.jdt.ui.TypeHierarchy"/>
 -<show_view_action id="org.eclipse.jdt.ui.SourceView"/>
 -<show_view_action id="org.eclipse.jdt.ui.JavadocView"/>
 -<show_view_action id="org.eclipse.search.ui.views.SearchView"/>
 -<show_view_action id="org.eclipse.ui.console.ConsoleView"/>
 -<show_view_action id="org.eclipse.ui.views.ContentOutline"/>
 -<show_view_action id="org.eclipse.ui.views.ProblemView"/>
 -<show_view_action id="org.eclipse.ui.views.ResourceNavigator"/>
 -<show_view_action id="org.eclipse.ui.views.TaskList"/>
 -<show_view_action id="org.eclipse.ui.views.ProgressView"/>
 -<show_view_action id="org.eclipse.ant.ui.views.AntView"/>
 -<show_view_action id="org.eclipse.pde.runtime.LogView"/>
 -<new_wizard_action id="org.eclipse.jdt.ui.wizards.NewPackageCreationWizard"/>
 -<new_wizard_action id="org.eclipse.jdt.ui.wizards.NewClassCreationWizard"/>
 -<new_wizard_action id="org.eclipse.jdt.ui.wizards.NewInterfaceCreationWizard"/>
 -<new_wizard_action id="org.eclipse.jdt.ui.wizards.NewEnumCreationWizard"/>
 -<new_wizard_action id="org.eclipse.jdt.ui.wizards.NewAnnotationCreationWizard"/>
 -<new_wizard_action id="org.eclipse.jdt.ui.wizards.NewSourceFolderCreationWizard"/>
 -<new_wizard_action id="org.eclipse.jdt.ui.wizards.NewSnippetFileCreationWizard"/>
 -<new_wizard_action id="org.eclipse.ui.wizards.new.folder"/>
 -<new_wizard_action id="org.eclipse.ui.wizards.new.file"/>
 -<new_wizard_action id="org.eclipse.ui.editors.wizards.UntitledTextFileWizard"/>
 -<new_wizard_action id="org.eclipse.jdt.junit.wizards.NewTestCaseCreationWizard"/>
 -<perspective_action id="org.eclipse.jdt.ui.JavaPerspective"/>
 -<perspective_action id="org.eclipse.debug.ui.DebugPerspective"/>
 -<perspective_action id="org.eclipse.jdt.ui.JavaBrowsingPerspective"/>
 -<view id="org.eclipse.jdt.ui.PackageExplorer"/>
 -<view id="org.eclipse.jdt.ui.TypeHierarchy"/>
 -<view id="org.eclipse.ui.views.ProblemView"/>
 -<view id="org.eclipse.jdt.ui.JavadocView"/>
 -<view id="org.eclipse.jdt.ui.SourceView"/>
 -<view id="org.eclipse.ui.views.ContentOutline"/>
 -<view id="org.eclipse.ui.internal.introview"/>
 -<layout>
 -<mainWindow>
 -<info folder="true" part="left">
 -<folder activePageID="org.eclipse.jdt.ui.PackageExplorer" appearance="2" expanded="2">
 -<page content="org.eclipse.jdt.ui.PackageExplorer" label="Package Explorer"/>
 -<page content="org.eclipse.jdt.ui.TypeHierarchy" label="Hierarchy"/>
 -<page content="org.eclipse.ui.views.ResourceNavigator" label="LabelNotFound"/>
 -<page content="org.eclipse.jdt.junit.ResultView" label="LabelNotFound"/>
 -<presentation id="org.eclipse.ui.presentations.WorkbenchPresentationFactory">
 -<part id="0"/>
 -<part id="1"/>
 -</presentation>
 -</folder>
 -</info>
 -<info folder="true" part="org.eclipse.ui.internal.ViewStack@174f3b" ratio="0.7495069" ratioLeft="760" ratioRight="254" relationship="2" relative="left">
 -<folder activePageID="org.eclipse.ui.internal.introview" appearance="2" expanded="2">
 -<page content="org.eclipse.help.ui.HelpView" label="LabelNotFound"/>
 -<page content="org.eclipse.ui.internal.introview" label="Welcome"/>
 -<page content="org.eclipse.ui.cheatsheets.views.CheatSheetView" label="LabelNotFound"/>
 -<presentation id="org.eclipse.ui.presentations.WorkbenchPresentationFactory">
 -<part id="0"/>
 -</presentation>
 -</folder>
 -</info>
 -<info part="org.eclipse.ui.editorss" ratio="0.2495069" ratioLeft="253" ratioRight="761" relationship="2" relative="left"/>
 -<info folder="true" part="bottom" ratio="0.74932617" ratioLeft="556" ratioRight="186" relationship="4" relative="org.eclipse.ui.editorss">
 -<folder activePageID="org.eclipse.ui.views.ProblemView" appearance="2" expanded="2">
 -<page content="org.eclipse.ui.views.ProblemView" label="Problems"/>
 -<page content="org.eclipse.jdt.ui.JavadocView" label="Javadoc"/>
 -<page content="org.eclipse.jdt.ui.SourceView" label="Declaration"/>
 -<page content="org.eclipse.search.ui.views.SearchView" label="LabelNotFound"/>
 -<page content="org.eclipse.ui.console.ConsoleView" label="LabelNotFound"/>
 -<page content="org.eclipse.ui.views.BookmarkView" label="LabelNotFound"/>
 -<page content="org.eclipse.ui.views.ProgressView" label="LabelNotFound"/>
 -<presentation id="org.eclipse.ui.presentations.WorkbenchPresentationFactory">
 -<part id="0"/>
 -<part id="1"/>
 -<part id="2"/>
 -</presentation>
 -</folder>
 -</info>
 -<info folder="true" part="org.eclipse.ui.internal.ViewStack@b5d678" ratio="0.74901444" ratioLeft="570" ratioRight="191" relationship="2" relative="org.eclipse.ui.editorss">
 -<folder activePageID="org.eclipse.ui.views.ContentOutline" appearance="2" expanded="2">
 -<page content="org.eclipse.ui.views.ContentOutline" label="Outline"/>
 -<page content="org.eclipse.ant.ui.views.AntView" label="LabelNotFound"/>
 -<presentation id="org.eclipse.ui.presentations.WorkbenchPresentationFactory">
 -<part id="0"/>
 -</presentation>
 -</folder>
 -</info>
 -</mainWindow>
 -</layout>
 -</perspective>
 -</perspectives>
 -<workingSets/>
 -<navigationHistory/>
 -<stickyState/>
 -<input factoryID="org.eclipse.ui.internal.model.ResourceFactory" path="/" type="8"/>
 -</page>
 -<workbenchWindowAdvisor/>
 -<actionBarAdvisor/>
 -<trimLayout>
 -<trimArea IMemento.internal.id="128">
 -<trimItem IMemento.internal.id="org.eclipse.ui.internal.WorkbenchWindow.topBar"/>
 -</trimArea>
 -<trimArea IMemento.internal.id="1024">
 -<trimItem IMemento.internal.id="org.eclise.ui.internal.FastViewBar"/>
 -<trimItem IMemento.internal.id="org.eclipse.jface.action.StatusLineManager"/>
 -<trimItem IMemento.internal.id="org.eclipse.ui.internal.progress.ProgressRegion"/>
 -</trimArea>
 -</trimLayout>
 -</window>
 -<mruList/>
 -</workbench> 
 -<?xml version="1.0" encoding="UTF-8"?>
 -<projectDescription>
 -	<name>webpaos-local</name>
 -	<comment></comment>
 -	<projects>
 -	</projects>
 -	<buildSpec>
 -		<buildCommand>
 -			<name>net.sourceforge.phpeclipse.parserbuilder</name>
 -			<arguments>
 -			</arguments>
 -		</buildCommand>
 -	</buildSpec>
 -	<natures>
 -		<nature>net.sourceforge.phpeclipse.phpnature</nature>
 -	</natures>
 -</projectDescription>
 !SESSION 2007-07-03 12:00:48.815 -----------------------------------------------
 -eclipse.buildId=M20060921-0945
 -java.version=1.5.0_07
 -java.vendor=Apple Computer, Inc.
 -BootLoader constants: OS=macosx, ARCH=x86, WS=carbon, NL=en_US
 -Framework arguments:  -keyring /Users/nicolawilkinson/.eclipse_keyring -showlocation
 -Command-line arguments:  -os macosx -ws carbon -keyring /Users/nicolawilkinson/.eclipse_keyring -consoleLog -showlocation
 -
 -!ENTRY org.eclipse.osgi 4 0 2007-07-03 12:01:42.424
 -!MESSAGE While loading class "net.sourceforge.phpeclipse.PHPeclipsePlugin$3$1", thread "Worker-2" timed out waiting (5000ms) for thread "main" to finish starting bundle "net.sourceforge.phpeclipse". To avoid deadlock, thread "Worker-2" is proceeding but "net.sourceforge.phpeclipse.PHPeclipsePlugin$3$1" may not be fully initialized.
 -!STACK 0
 -java.lang.Exception: Generated exception.
 -	at org.eclipse.core.runtime.internal.adaptor.EclipseLazyStarter.preFindLocalClass(EclipseLazyStarter.java:75)
 -	at org.eclipse.osgi.baseadaptor.loader.ClasspathManager.findLocalClass(ClasspathManager.java:409)
 -	at org.eclipse.osgi.internal.baseadaptor.DefaultClassLoader.findLocalClass(DefaultClassLoader.java:188)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findLocalClass(BundleLoader.java:334)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findClass(BundleLoader.java:386)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findClass(BundleLoader.java:347)
 -	at org.eclipse.osgi.internal.baseadaptor.DefaultClassLoader.loadClass(DefaultClassLoader.java:83)
 -	at java.lang.ClassLoader.loadClass(ClassLoader.java:251)
 -	at java.lang.ClassLoader.loadClassInternal(ClassLoader.java:319)
 -	at net.sourceforge.phpeclipse.PHPeclipsePlugin$3.run(PHPeclipsePlugin.java:1182)
 -	at org.eclipse.core.internal.jobs.Worker.run(Worker.java:58)
View
-!SESSION 2007-07-03 12:00:48.815 -----------------------------------------------
 -eclipse.buildId=M20060921-0945
 -java.version=1.5.0_07
 -java.vendor=Apple Computer, Inc.
 -BootLoader constants: OS=macosx, ARCH=x86, WS=carbon, NL=en_US
 -Framework arguments:  -keyring /Users/nicolawilkinson/.eclipse_keyring -showlocation
 -Command-line arguments:  -os macosx -ws carbon -keyring /Users/nicolawilkinson/.eclipse_keyring -consoleLog -showlocation
 -
 -!ENTRY org.eclipse.osgi 4 0 2007-07-03 12:01:42.424
 -!MESSAGE While loading class "net.sourceforge.phpeclipse.PHPeclipsePlugin$3$1", thread "Worker-2" timed out waiting (5000ms) for thread "main" to finish starting bundle "net.sourceforge.phpeclipse". To avoid deadlock, thread "Worker-2" is proceeding but "net.sourceforge.phpeclipse.PHPeclipsePlugin$3$1" may not be fully initialized.
 -!STACK 0
 -java.lang.Exception: Generated exception.
 -	at org.eclipse.core.runtime.internal.adaptor.EclipseLazyStarter.preFindLocalClass(EclipseLazyStarter.java:75)
 -	at org.eclipse.osgi.baseadaptor.loader.ClasspathManager.findLocalClass(ClasspathManager.java:409)
 -	at org.eclipse.osgi.internal.baseadaptor.DefaultClassLoader.findLocalClass(DefaultClassLoader.java:188)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findLocalClass(BundleLoader.java:334)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findClass(BundleLoader.java:386)
 -	at org.eclipse.osgi.framework.internal.core.BundleLoader.findClass(BundleLoader.java:347)
 -	at org.eclipse.osgi.internal.baseadaptor.DefaultClassLoader.loadClass(DefaultClassLoader.java:83)
 -	at java.lang.ClassLoader.loadClass(ClassLoader.java:251)
 -	at java.lang.ClassLoader.loadClassInternal(ClassLoader.java:319)
 -	at net.sourceforge.phpeclipse.PHPeclipsePlugin$3.run(PHPeclipsePlugin.java:1182)
 -	at org.eclipse.core.internal.jobs.Worker.run(Worker.java:58)

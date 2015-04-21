# BioID.Owin.OAuth
BioID OAuth 2.0 client middleware for OWIN.

## Install
Before you can use this client software, you have to login to BioID (e.g. at https://playground.bioid.com/account/login), navigate to https://bioid.bioid.com/manage/clients and create a new BioID client ID to get your unique ID and secret.

### Install the client via NuGet Package:
You can easily install the BioID OAuth 2.0 client OWIN middleware using the NuGet Package Manager console in Visual Studio:
```
PM> Install-Package BioID.Owin.OAuth
```

## Usage
To add the middleware to the OWIN pipeline, you simply add the namespace `BioID.Owin.OAuth` and the following code to your OWIN startup code, e.g. in `Startup.Auth.cs` in case of an VS 2013 Web App:
```
using BioID.Owin.OAuth;
//...
public void ConfigureAuth(IAppBuilder app)
{
  //...
  app.UseBioIDAuthentication(
    clientId: "", 
    clientSecret: "");
    
  // or, if you want to apply more options like additional scopes:
  
  var options = new BioIDAuthenticationOptions
  {
    ClientId = "",
    ClientSecret = "",
    AuthenticationType = "BioID",
    //...
  };
  options.Scope.Add("email");
  app.UseBioIDAuthentication(options);
  //...
}
//...
```

### See also
Refer to the [BioID OAuth 2.0 documentation](https://playground.bioid.com/BioIDOAuth) for more information.

## License
under [MIT License](http://opensource.org/licenses/MIT)

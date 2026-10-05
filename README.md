# Wraithfeed 

```ASCII
                                               .         s                                                   ..       
  x=~                                         @88>      :8      .uef^"       oec :                         dF         
 88x.   .e.   .e.     .u    .                 %8P      .88    :d88E         @88888                        '88bu.      
'8888X.x888:.x888   .d88B :@8c        u        .      :888ooo `888E         8"*88%       .u         .u    '*88888bu   
 `8888  888X '888k ="8888f8888r    us888u.   .@88u  -*8888888  888E .z8k    8b.       ud8888.    ud8888.    ^"*8888N  
  X888  888X  888X   4888>'88"  .@88 "8888" ''888E`   8888     888E~?888L  u888888> :888'8888. :888'8888.  beWE "888L 
  X888  888X  888X   4888> '    9888  9888    888E    8888     888E  888E   8888R   d888 '88%" d888 '88%"  888E  888E 
  X888  888X  888X   4888>      9888  9888    888E    8888     888E  888E   8888P   8888.+"    8888.+"     888E  888E 
 .X888  888X. 888~  .d888L .+   9888  9888    888E   .8888Lu=  888E  888E   *888>   8888L      8888L       888E  888F 
 `%88%``"*888Y"     ^"8888*"    9888  9888    888&   ^%888*    888E  888E   4888    '8888c. .+ '8888c. .+ .888N..888  
   `~     `"           "Y"      "888*""888"   R888"    'Y"    m888N= 888>   '888     "88888%    "88888%    `"888*""   
                                 ^Y"   ^Y'     ""              `Y"   888     88R       "YP'       "YP'        ""      
                                                                    J88"     88>                                      
                                                                    @%       48                                       
                                                                  :"         '8                                       
```

`Wraithfeed` is an autonomous threat intelligence pipeline that ingests CVE/KEV and malware feeds, scores and prioritizes findings, generates analyst-ready briefings, and pushes structured events to MISP. Built for lean security teams who need signal, not noise, from the threat landscape. 👻📡

Created: August 5, 2026

* Initially a portfolio piece
* You can also take a look at my SBOM scanning vulnerability tool called [KEVScan](https://kevscan.cloud/) which may have a minimal level of external functionality.

* 

## Features

* Extracts IOCs from a test article: 20260805
* Stage 6 and save to MISP tested successful: 20261004


# References

* [MalwareBazzar Community API](https://bazaar.abuse.ch/api/) (this is currently a portfolio project)

# Experiential Notes

* I learned how to use `pytest`.
* I learned more about Pythonisms like using `_` as a throw-away variable and using `type_` as a variable name to avoid confusion with the `type` keyword, but argued with Claude that `indicator_type` would be a better variable name. I'm ol' school.
* On the Claude Pro Plan it really doesn't cost anything extra if you're only coding for a couple of hours a day. It's a nice change from my Hermes Agent project which runs solely on API credits from a number of model providers.



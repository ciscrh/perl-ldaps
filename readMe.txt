I developed these scripts to manage several Novell eDirectories and 
MS Active Directories and later updated them to work with Apache 
Directory Services.

The scripts used for most tasks were ldapAdd.pl, ldapDelete.pl, 
ldapModify.pl and ldapSearch.pl.

Some of the scripts were blind alleys that were abandoned; the version 
history gives a clue here in that the successful scripts have more versions.

I had a problem working with LDIF in that I found the rigid syntax too fussy 
when applied to the routine uses that I needed it for. Over time I developed 
the LDAP entry records and files to work with my scripts as a simpler
alternative to LDIF.

LDAP entry records and files are explained in some detail in the 
entryFiles.txt file.
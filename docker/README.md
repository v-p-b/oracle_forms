Build the container:

```
docker build . -t oracle_forms
```

Run the container:

```
docker run -p 8081:8081 --rm -it oracle_forms 
```

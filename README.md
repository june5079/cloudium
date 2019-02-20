# Cloudium

Cloudium is certification-info. extractor from global cloud provider
for security researcher, cloud operators.

<p align="left">
    <img src="http://noplanlife.com/sample2.svg">
</p>

## Getting Started

Tested on linux based OS + Python3 but Windows OS is OK (just I'm not familiar with)

Prepare keywords what you want to find from SSL certification information.

Cloudium only extract "CN" info but, you can modify codes to get other info.

### Dependencies

Python3.x is highly recommended for this tool.
Simply can install packages with command below.

```sudo pip install -r requirements.txt```

### Example

Search keywords from cloud service providers.
Cloudium supports aws|azure|gcloud
Region depends on what provider you choose 

```
python3 main.py -p amazon -k KEYWORD1 KEYWORD2 KEYWORD3 -o KEYWORD_OUT.txt -r us
```

Step 0x02 : Get digging with extracted information. - (On development)

## Authors

**June Park** - *SANE(Security Analysis and Evaluation) Lab in Korea Unviersity* - [Noplanlife.com](https://noplanlife.com)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details



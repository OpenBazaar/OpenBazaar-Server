from protos import objects
import csv
import os
from config import DATA_FOLDER
from collections import OrderedDict
import json
import base64
import requests
from protos.countries import CountryCode


def migratev2(db):
    ser = db.listings.get_proto()
    if ser is not None:
        path = os.path.join(DATA_FOLDER, "listings.csv")
        with open(path, 'w') as csvfile:
            fieldnames = ["contract_type", "pricing_currency", "language", "title", "description", "processing_time",
                          "price", "nsfw", "image_urls", "categories", "condition", "quantity", "sku_number",
                          "shipping_option1_name", "shipping_option1_countries", "shipping_option1_service1_name",
                          "shipping_option1_service1_estimated_delivery", "shipping_option1_service1_estimated_price",
                          "shipping_option2_name", "shipping_option2_countries", "shipping_option2_service1_name",
                          "shipping_option2_service1_estimated_delivery", "shipping_option2_service1_estimated_price"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            l = objects.Listings()
            l.ParseFromString(ser)
            for listing in l.listing:
                with open(db.filemap.get_file(listing.contract_hash.encode("hex")), "r") as filename:
                    contract = json.loads(filename.read(), object_pairs_hook=OrderedDict)

                price = ""
                if listing.currency_code.lower() == "btc":
                    price = contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["bitcoin"]
                    price = int(price * 100000000)
                else:
                    price = contract["vendor_offer"]["listing"]["item"]["price_per_unit"]["fiat"]["price"]

                sku = ""
                if "sku" in contract["vendor_offer"]["listing"]["item"]:
                    sku = contract["vendor_offer"]["listing"]["item"]["sku"]

                condition = ""
                if "condition" in contract["vendor_offer"]["listing"]["item"]:
                    condition = contract["vendor_offer"]["listing"]["item"]["condition"]

                category = ""
                if "category" in contract["vendor_offer"]["listing"]["item"]:
                    category = contract["vendor_offer"]["listing"]["item"]["category"]

                contract_type = "PHYSICAL_GOOD"
                if contract["vendor_offer"]["listing"]["metadata"]["category"] == "digital good":
                    contract_type = "DIGITAL_GOOD"

                row = {
                    'contract_type': contract_type,
                    'pricing_currency': listing.currency_code,
                    'language': 'english',
                    'title': listing.title,
                    'description': contract["vendor_offer"]["listing"]["item"]["description"],
                    'processing_time': contract["vendor_offer"]["listing"]["item"]["process_time"],
                    'price': price,
                    'nsfw': str(listing.nsfw),
                    'image_urls': '',
                    'categories': category,
                    'condition': condition,
                    'quantity': '-1',
                    'sku_number': sku
                }
                img64 = []
                for img_hash in contract["vendor_offer"]["listing"]["item"]["image_hashes"]:
                    image_path = db.filemap.get_file(img_hash)
                    with open(image_path, "rb") as image_file:
                        encoded_string = base64.b64encode(image_file.read())
                    img64.append(encoded_string)
                if len(img64) == 1:
                    row["image_urls"] = img64[0]
                else:
                    img_csv = ''
                    r = 0
                    for img in img64:
                        r += 1
                        img_csv += img
                        if r != len(img64):
                            img_csv += ","
                    row["image_urls"] = img_csv
                if contract_type == "PHYSICAL_GOOD":
                    if "free" in contract["vendor_offer"]["listing"]["shipping"]:
                        row["shipping_option1_name"] = "Free Shipping"
                        countries = []
                        for country in listing.ships_to:
                            countries.append(str(CountryCode.Name(country)))
                        if len(countries) == 1:
                            row["shipping_option1_countries"] = countries[0]
                        else:
                            country_csv = ''
                            r = 0
                            for c in countries:
                                r += 1
                                country_csv += c
                                if r != len(countries):
                                    country_csv += ","
                            row["shipping_option1_countries"] = country_csv
                        row["shipping_option1_service1_name"] = "default service"
                        ed = "standard shipping time"
                        row["shipping_option1_service1_estimated_delivery"] = ed
                        row["shipping_option1_service1_estimated_price"] = "0"
                    elif "flat_fee" in contract["vendor_offer"]["listing"]["shipping"]:
                        cc = "bitcoin"
                        if listing.currency_code.lower() != "btc":
                            cc = "fiat"
                        if "domestic" in contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][cc]["price"]:
                            row["shipping_option1_name"] = "Domestic Shipping"
                            row["shipping_option1_countries"] = contract["vendor_offer"]["listing"]["shipping"][
                                "shipping_origin"]
                            row["shipping_option1_service1_name"] = "default service"
                            ed = contract["vendor_offer"]["listing"]["shipping"]["est_delivery"]["domestic"]
                            if ed == "":
                                ed = "standard shipping time"
                            row["shipping_option1_service1_estimated_delivery"] = ed
                            ship_price = contract["vendor_offer"]["listing"][
                                "shipping"]["flat_fee"][cc]["price"]["domestic"]
                            if cc == "bitcoin":
                                ship_price = int(ship_price * 100000000)
                            row["shipping_option1_service1_estimated_price"] = ship_price
                        if "international" in contract["vendor_offer"]["listing"]["shipping"]["flat_fee"][cc]["price"]:
                            row["shipping_option2_name"] = "International Shipping"
                            countries = []
                            for country in listing.ships_to:
                                countries.append(str(CountryCode.Name(country)))
                            if len(countries) == 1:
                                row["shipping_option2_countries"] = countries[0]
                            else:
                                country_csv = ''
                                r = 0
                                for c in countries:
                                    r += 1
                                    country_csv += c
                                    if r != len(countries):
                                        country_csv += ","
                                row["shipping_option2_countries"] = country_csv
                            row["shipping_option2_service1_name"] = "default service"
                            ed = contract["vendor_offer"]["listing"]["shipping"]["est_delivery"]["international"]
                            if ed == "":
                                ed = "standard shipping time"
                            row["shipping_option2_service1_estimated_delivery"] = ed
                            row["shipping_option2_service1_estimated_price"] = contract["vendor_offer"]["listing"][
                                "shipping"]["flat_fee"][cc]["price"]["domestic"]

                writer.writerow(row)
        return path
    else:
        raise Exception("failed to deserialize listings")

while read -r org; do
    # Remove carriage return if present
    org=$(echo "$org" | tr -d '\r')
    echo "Processing $org"
    echo "$org" > org_${org}.txt
    python ./scripts/list_org_repositories.py -i org_${org}.txt -o repos_${org}.json >> list_org_repos_per_org.log 2>&1
    rm org_${org}.txt
done < "$1"

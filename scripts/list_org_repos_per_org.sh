while read -r org; do
    # Remove carriage return if present
    org=$(echo "$org" | tr -d '\r')
    echo "Processing $org"
    echo "$org" > org_${org}.txt
    python ./scripts/list_org_repositories.py -i org_${org}.txt -o micro_repos_${org}.json >> micro_list_org_repos_per_org.log 2>&1
    rm org_${org}.txt
done < "$1"

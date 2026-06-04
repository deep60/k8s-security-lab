#!/bin/bash
echo "=== Cluster-Admin Bindings ==="
kubectl get clusterrolebindings -o json |   jq '.items[] | select(.roleRef.name=="cluster-admin") | {name: .metadata.name, subjects: .subjects}'

echo ""
echo "=== All RoleBindings per Namespace ==="
kubectl get rolebindings --all-namespaces -o wide

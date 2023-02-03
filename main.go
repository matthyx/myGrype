package main

import (
	"fmt"
	"os"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft"
)

func getMatchers() []matcher.Matcher {
	return matcher.NewDefaultMatchers(
		matcher.Config{
			Java: java.MatcherConfig{
				ExternalSearchConfig: java.ExternalSearchConfig{MavenBaseURL: "https://search.maven.org/solrsearch/select"},
				UseCPEs:              true,
			},
			Ruby:       ruby.MatcherConfig{UseCPEs: true},
			Python:     python.MatcherConfig{UseCPEs: true},
			Dotnet:     dotnet.MatcherConfig{UseCPEs: true},
			Javascript: javascript.MatcherConfig{UseCPEs: true},
			Golang:     golang.MatcherConfig{UseCPEs: true},
			Stock:      stock.MatcherConfig{UseCPEs: true},
		},
	)
}

func shouldUpdateDB(dbCurator db.Curator) bool {
	return dbCurator.Status().Err != nil || dbCurator.Status().Built.Add(120*time.Hour).Before(time.Now())
}

func updateDB(dbCurator db.Curator) error {
	fmt.Println("downloading db")
	updated, err := dbCurator.Update()
	if err != nil {
		return err
	}
	if updated {
		fmt.Println("db was updated")
	}
	return nil
}

func main() {
	// check vuln DB
	dbConfig := db.Config{
		DBRootDir:  "matthiasgrypedb",
		ListingURL: "https://toolbox-data.anchore.io/grype/databases/listing.json",
	}
	dbCurator, err := db.NewCurator(dbConfig)
	if err != nil {
		panic(err)
	}
	if shouldUpdateDB(dbCurator) {
		err := updateDB(dbCurator)
		if err != nil {
			panic(err)
		}
	}
	// load vuln DB
	str, status, dbCloser, err := grype.LoadVulnerabilityDB(dbConfig, false)
	if dbCloser != nil {
		defer dbCloser.Close()
	}
	if err != nil {
		panic(err)
	}
	// read SBOM
	sbomFile, err := os.Open("nginx-sbom-spdx-json-foramt.json")
	defer sbomFile.Close()
	if err != nil {
		panic(err)
	}
	sbom, _, err := syft.Decode(sbomFile)
	// scan SBOM
	packages := pkg.FromCatalog(sbom.Artifacts.PackageCatalog, pkg.SynthesisConfig{})
	if err != nil {
		panic(err)
	}
	pkgContext := pkg.Context{
		Source: &sbom.Source,
		Distro: sbom.Artifacts.LinuxDistribution,
	}
	vulnMatcher := grype.VulnerabilityMatcher{
		Store:    *str,
		Matchers: getMatchers(),
	}
	remainingMatches, ignoredMatches, err := vulnMatcher.FindMatches(packages, pkgContext)
	if err != nil {
		panic(err)
	}
	// generate JSON
	presenterConfig := models.PresenterConfig{
		Matches:          *remainingMatches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		Context:          pkgContext,
		MetadataProvider: str,
		SBOM:             sbom,
		AppConfig:        nil,
		DBStatus:         status,
	}
	presenter := json.NewPresenter(presenterConfig)
	cveFile, err := os.Create("cve.json")
	defer cveFile.Close()
	if err != nil {
		panic(err)
	}
	err = presenter.Present(cveFile)
	if err != nil {
		panic(err)
	}
}
